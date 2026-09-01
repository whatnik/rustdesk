// Headless (no GUI/Flutter) клиент для RustDesk-режима Terminal.
//
// Обычный клиент (`rustdesk.exe --terminal <ID> --password <PWD>`) целиком
// завязан на Flutter FFI (`core_main.rs`, `#[cfg(feature = "flutter")]`) —
// это то же GUI-приложение, просто открывающее окно с терминальным виджетом.
// Здесь — тот же сетевой/протокольный путь (`client::Client::start`,
// `client::Interface`, `client::handle_hash`), но без единой строчки GUI:
// ввод/вывод — обычные stdin/stdout текущего процесса.
//
// Живёт внутри библиотечного крейта (не отдельным bin с `extern crate`)
// потому что модуль `client` в lib.rs объявлен как `mod client;` (приватный,
// не `pub`) — доступ к `Client`/`Interface`/`handle_hash` есть только у кода
// внутри самого крейта `librustdesk`, как у `core_main.rs`/`ui.rs`.
//
// Terminal (Run as administrator) — тот же пункт меню, что в официальном
// Flutter-клиенте (`peer_card.dart::_terminalRunAsAdminAction`, подписан
// "Terminal (Run as administrator) (beta)"), реализован здесь тем же
// протокольным путём, без единой правки на стороне сервера/управляемой
// машины. Механизм (разобран по `src/client.rs`):
//   1. Перед `LoginConfigHandler::initialize()` выставляем env
//      `IS_TERMINAL_ADMIN=Y` — `initialize()` читает её один раз и на её
//      основе взводит `is_terminal_admin` (ровно то же самое, что делает
//      Flutter-сторона через `setEnvTerminalAdmin()`/`mainSetEnv`).
//   2. `client::handle_hash()` (вызывается уже отсюда, через
//      `Interface::handle_hash`) при `is_terminal_admin=true` НЕ шлёт
//      LoginRequest сразу — вместо этого показывает msgbox
//      "terminal-admin-login" (обычный пароль уже известен из --password)
//      или "terminal-admin-login-password" (нужен ещё и он) и молча
//      возвращается, сохранив `hash` в `lc`.
//   3. Официальный клиент в ответ на этот msgbox открывает диалог,
//      собирает admin-логин/пароль УПРАВЛЯЕМОЙ стороны и зовёт
//      `Interface::handle_login_from_ui(os_username, os_password, ...)`.
//      Мы делаем то же самое сразу после `handle_hash()`, без диалога —
//      либо из `--admin-user`/`--admin-password`, либо интерактивным
//      промптом (см. `prompt_line`/`prompt_password`).
//   4. `handle_login_from_ui()` досчитывает hash пароля подключения (или
//      берёт уже известный из lc, если сам не передан) и шлёт LoginRequest
//      с заполненным `OSLogin{username, password}` — это и есть тот самый
//      admin-логин, дальше (`CreateProcessWithLogonW` на управляемой
//      Windows-машине) целиком на стороне терминального сервиса, нашего
//      кода не касается.
// Наш --password ВСЕГДА задан (обязательный CLI-аргумент, см. bin/), так
// что реально достижим только вариант "terminal-admin-login" — второй
// параметр `handle_login_from_ui` (password подключения) поэтому всегда
// пустая строка, что означает "переиспользовать уже известный в lc".

use async_trait::async_trait;
use crate::client::{self, Client, Data, Interface, LoginConfigHandler};
use hbb_common::{
    bail,
    config::LocalConfig,
    message_proto::{self, message, terminal_response, *},
    protobuf::Message as _,
    rendezvous_proto::ConnType,
    tokio::{self, sync::mpsc},
    ResultType, Stream,
};
use std::{
    fs::File,
    io::{BufRead, Write},
    process::Command,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct HeadlessInterface {
    lc: Arc<RwLock<LoginConfigHandler>>,
}

#[async_trait]
impl Interface for HeadlessInterface {
    fn send(&self, _data: Data) {}

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, _link: &str) {
        if msgtype == "terminal-admin-login" || msgtype == "terminal-admin-login-password" {
            // title/text у этого события всегда пустые (см. client.rs,
            // interface.msgbox(..., "", "", "")) — реальный запрос admin-
            // логина обрабатывается сразу после handle_hash() в run(), не
            // здесь (msgbox синхронный и без доступа к peer/lc-записи).
            eprintln!("[terminal] управляемая сторона запросила admin-логин ({msgtype})");
            return;
        }
        eprintln!("[{msgtype}] {title}: {text}");
    }

    fn handle_login_error(&self, err: &str) -> bool {
        eprintln!("login error: {err}");
        false
    }

    fn handle_peer_info(&self, pi: message_proto::PeerInfo) {
        eprintln!(
            "[connected] hostname={} platform={} version={}",
            pi.hostname, pi.platform, pi.version
        );
    }

    fn set_multiple_windows_session(&self, _sessions: Vec<WindowsSession>) {}

    async fn handle_hash(&self, pass: &str, hash: message_proto::Hash, peer: &mut Stream) {
        client::handle_hash(self.lc.clone(), pass, hash, self, peer).await;
    }

    async fn handle_login_from_ui(
        &self,
        os_username: String,
        os_password: String,
        password: String,
        remember: bool,
        peer: &mut Stream,
    ) {
        // Обычный (не terminal-admin) повторный ввод пароля через UI сюда
        // не попадает — пароль всегда приходит из CLI заранее (handle_hash).
        // Единственный вызывающий — run(), сразу после handle_hash(), для
        // admin-логина (см. докстринг модуля выше).
        client::handle_login_from_ui(self.lc.clone(), os_username, os_password, password, remember, peer)
            .await;
    }

    async fn handle_test_delay(&self, _t: message_proto::TestDelay, _peer: &mut Stream) {}

    fn get_lch(&self) -> Arc<RwLock<LoginConfigHandler>> {
        self.lc.clone()
    }
}

fn stty(args: &[&str]) {
    // Без внешних крейтов (termios/crossterm) — `stty` есть в системе Linux
    // всегда, доверяем ему; ошибки не фатальны (например, stdin — не tty,
    // при пайпе/тестах), просто пишем в stderr.
    if let Err(e) = Command::new("stty").args(args).status() {
        eprintln!("stty {args:?} failed: {e}");
    }
}

fn enable_raw_mode() {
    stty(&["raw", "-echo"]);
}

fn disable_raw_mode() {
    stty(&["sane"]);
}

/// Реальный размер терминала (`stty size` -> "ROWS COLS"), если stdin —
/// настоящий tty. None, если не удалось узнать (пайп/редирект/не-tty) —
/// тогда вызывающий код сам решает, на что откатиться.
fn terminal_size() -> Option<(u32, u32)> {
    let out = Command::new("stty").arg("size").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let mut it = s.split_whitespace();
    let rows: u32 = it.next()?.parse().ok()?;
    let cols: u32 = it.next()?.parse().ok()?;
    Some((rows, cols))
}

/// RAII-страховка: без нашего явного контроля `stty raw -echo` может
/// остаться навсегда, если функция выйдет ДОСРОЧНО (любой `?` после
/// enable_raw_mode() — например `peer.send(...).await?` рвётся сетевой
/// ошибкой ровно в момент, когда удалённая сторона закрывает сессию по
/// `exit`) — раньше `disable_raw_mode()` стоял только в конце функции и
/// пропускался при любом таком раннем выходе, оставляя терминал
/// пользователя в сыром режиме без эха (симптом, живьём найденный
/// 2026-08-22: "сессия повисла, пришлось закрывать родительский
/// терминал" — на деле процесс уже завершился, просто termios не
/// восстановлен). `Drop` вызывается при возврате из функции любым путём
/// (return/`?`/паника при unwind), поэтому это надёжнее, чем звать
/// disable_raw_mode() в конце по обычному потоку исполнения.
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        disable_raw_mode();
    }
}

pub struct HeadlessTerminalArgs {
    pub id: String,
    pub password: String,
    /// None — узнать реальный размер локального терминала (stty size) при
    /// подключении; если это не удалось (не tty) — откат на 24x80.
    pub rows: Option<u32>,
    pub cols: Option<u32>,
    /// Путь к отладочному логу — если задан, туда пишутся сырые байты в
    /// обе стороны (после распаковки, то есть ровно то, что реально
    /// летит в stdout/из stdin) с таймстампами, плюс ключевые события
    /// (Opened/Closed/ошибки). Заведено 2026-08-22 для разбора двух живых
    /// находок: "прыжки курсора на ls" (PowerShell/PSReadLine поверх
    /// ConPTY может слать запрос позиции курсора ESC[6n и ждать ответа
    /// ESC[row;colR — интересно, что реально приходит и уходит) и
    /// "задержка перед выходом после exit" (когда именно приходит
    /// TerminalClosed относительно последнего отправленного chunk'а).
    pub debug_log: Option<String>,
    /// Открыть терминал от имени администратора управляемой стороны — как
    /// пункт "Terminal (Run as administrator) (beta)" в официальном
    /// клиенте. Не путать с `password` (это обычный пароль RustDesk-
    /// подключения, нужен всегда) — admin_user/admin_password — это ОТДЕЛЬНАЯ
    /// пара, учётные данные Windows-аккаунта на управляемой машине. Если
    /// заданы --admin, но не --admin-user/--admin-password — спрашиваются
    /// интерактивно (см. prompt_line/prompt_password).
    pub admin: bool,
    pub admin_user: Option<String>,
    pub admin_password: Option<String>,
}

/// Прочитать строку с клавиатуры (видимо) — для --admin-user, если не
/// передан аргументом.
fn prompt_line(prompt: &str) -> String {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    s.trim_end_matches(['\n', '\r']).to_string()
}

/// То же самое, но без эха на терминале (`stty -echo`) — для пароля.
/// Тот же `stty`-приём, что enable_raw_mode/disable_raw_mode; здесь
/// применяется ДО того, как поток на stdin вообще запущен (см. run()) —
/// конкурентного чтения fd не возникает.
fn prompt_password(prompt: &str) -> String {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    stty(&["-echo"]);
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    stty(&["echo"]);
    eprintln!();
    s.trim_end_matches(['\n', '\r']).to_string()
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Дамп сырых байт в отладочный лог — Debug-форматирование через
/// `String::from_utf8_lossy` человекочитаемо показывает control/escape-
/// последовательности как `\u{1b}[...` и не падает на не-UTF8 байтах.
fn debug_dump(log: &mut Option<File>, dir: &str, data: &[u8]) {
    let Some(f) = log else { return };
    let text = String::from_utf8_lossy(data);
    let _ = writeln!(f, "{} {dir} {}B {:?}", now_ms(), data.len(), text);
    let _ = f.flush();
}

fn debug_event(log: &mut Option<File>, text: &str) {
    let Some(f) = log else { return };
    let _ = writeln!(f, "{} EVENT {text}", now_ms());
    let _ = f.flush();
}

pub async fn run(args: HeadlessTerminalArgs) -> ResultType<()> {
    if !crate::common::global_init() {
        bail!("global_init failed");
    }

    // Спрашиваем admin-логин ДО подключения (а не реактивно, по msgbox от
    // сервера) — раз --admin передан явно, событие "terminal-admin-login"
    // придёт гарантированно (см. докстринг модуля), незачем ждать его,
    // чтобы понять, что креды нужны. Важно сделать это ДО спавна потока,
    // читающего stdin ниже — иначе он и наш прямой read_line() дрались бы
    // за один и тот же fd.
    //
    // Приоритет источника креды: --admin-user/--admin-password (явно
    // указаны при подключении) > переменные окружения
    // HEADLESS_TERMINAL_ADMIN_USER/_PASSWORD (дефолт для повседневного
    // использования — чтобы просто "--admin" не спрашивал пароль каждый
    // раз, как и подключение без --admin вообще не спрашивает пароль
    // текущего пользователя) > интерактивный промпт (последний резерв,
    // если ни то ни другое не задано).
    let (admin_user, admin_password) = if args.admin {
        let user = args
            .admin_user
            .clone()
            .or_else(|| std::env::var("HEADLESS_TERMINAL_ADMIN_USER").ok())
            .unwrap_or_else(|| prompt_line("OS admin username (управляемая сторона): "));
        let password = args
            .admin_password
            .clone()
            .or_else(|| std::env::var("HEADLESS_TERMINAL_ADMIN_PASSWORD").ok())
            .unwrap_or_else(|| prompt_password("OS admin password: "));
        (user, password)
    } else {
        (String::new(), String::new())
    };

    let lc = Arc::new(RwLock::new(LoginConfigHandler::default()));
    // IS_TERMINAL_ADMIN читается один раз внутри initialize() (тем же
    // способом, что Flutter-сторона через setEnvTerminalAdmin()) — снимаем
    // сразу после, чтобы не протечь в состояние процесса дальше положенного.
    if args.admin {
        std::env::set_var("IS_TERMINAL_ADMIN", "Y");
    }
    lc.write()
        .unwrap()
        .initialize(args.id.clone(), ConnType::TERMINAL, None, false, None, None, None);
    if args.admin {
        std::env::remove_var("IS_TERMINAL_ADMIN");
    }
    let iface = HeadlessInterface { lc: lc.clone() };

    let key = crate::get_key(false).await;
    let token = LocalConfig::get_option("access_token");

    let mut dlog: Option<File> = match &args.debug_log {
        Some(path) => match std::fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(f) => {
                eprintln!("[debug-log: {path}]");
                Some(f)
            }
            Err(e) => {
                eprintln!("не удалось открыть debug-log {path}: {e}");
                None
            }
        },
        None => None,
    };

    eprintln!("Подключаюсь к {} (Terminal)...", args.id);
    let ((mut peer, _direct, _pk, _kcp, stream_type), (_feedback, _rendezvous_server)) =
        Client::start(&args.id, &key, &token, ConnType::TERMINAL, iface.clone()).await?;
    eprintln!("[transport: {stream_type}, secured={}]", peer.is_secured());

    let (init_rows, init_cols) = terminal_size().unwrap_or((24, 80));
    let init_rows = args.rows.unwrap_or(init_rows);
    let init_cols = args.cols.unwrap_or(init_cols);

    // SIGWINCH — сигнал о смене размера локального терминального окна.
    // tokio::signal::unix уже доступен транзитивно (feature "full" у
    // tokio в hbb_common) — новых зависимостей не требует. Без этого
    // удалённая сторона осталась бы зафиксирована на размере, который
    // был при подключении, даже если пользователь потом растянул/сузил
    // окно — см. объяснение в PR-обсуждении 2026-08-22.
    let mut winch = hbb_common::tokio::signal::unix::signal(
        hbb_common::tokio::signal::unix::SignalKind::window_change(),
    )?;

    // Читаем stdin в отдельном блокирующем потоке (обычный std::io::stdin
    // блокирующий; после `stty raw` он отдаёт байты по одному нажатию,
    // без построчной буферизации) и пробрасываем чанки в async-мир каналом.
    let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match std::io::Read::read(&mut std::io::stdin(), &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stdin_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut opened = false;
    // Живёт до конца функции — Drop восстановит терминал при ЛЮБОМ выходе
    // (нормальном break, `?`, панике), не только при штатном завершении
    // цикла. См. докстринг RawModeGuard.
    let mut _raw_guard: Option<RawModeGuard> = None;

    loop {
        tokio::select! {
            res = peer.next() => {
                match res {
                    Some(Ok(bytes)) => {
                        let Ok(msg_in) = Message::parse_from_bytes(&bytes) else { continue };
                        match msg_in.union {
                            Some(message::Union::Hash(hash)) => {
                                iface.handle_hash(&args.password, hash, &mut peer).await;
                                if args.admin {
                                    // handle_hash() выше при is_terminal_admin=true уже
                                    // показал msgbox и вернулся, ничего не отправив —
                                    // теперь досылаем LoginRequest с OSLogin сами (см.
                                    // докстринг модуля). password="" — переиспользовать
                                    // уже известный в lc (наш --password всегда задан).
                                    iface
                                        .handle_login_from_ui(
                                            admin_user.clone(),
                                            admin_password.clone(),
                                            String::new(),
                                            false,
                                            &mut peer,
                                        )
                                        .await;
                                }
                            }
                            Some(message::Union::LoginResponse(lr)) => match lr.union {
                                Some(login_response::Union::Error(err)) => {
                                    eprintln!("login error: {err}");
                                    return Ok(());
                                }
                                Some(login_response::Union::PeerInfo(pi)) => {
                                    iface.handle_peer_info(pi);
                                    let mut open = OpenTerminal::new();
                                    open.terminal_id = 0;
                                    open.rows = init_rows;
                                    open.cols = init_cols;
                                    let mut action = TerminalAction::new();
                                    action.set_open(open);
                                    let mut m = Message::new();
                                    m.set_terminal_action(action);
                                    peer.send(&m).await?;
                                }
                                _ => {}
                            },
                            Some(message::Union::TerminalResponse(tr)) => match tr.union {
                                Some(terminal_response::Union::Opened(o)) => {
                                    if o.success {
                                        opened = true;
                                        eprintln!("[terminal opened, pid={}]", o.pid);
                                        debug_event(&mut dlog, &format!("Opened pid={}", o.pid));
                                        enable_raw_mode();
                                        _raw_guard = Some(RawModeGuard);
                                    } else {
                                        eprintln!("не удалось открыть терминал: {}", o.message);
                                        debug_event(&mut dlog, &format!("Opened FAILED: {}", o.message));
                                        return Ok(());
                                    }
                                }
                                Some(terminal_response::Union::Data(d)) => {
                                    let data = if d.compressed {
                                        hbb_common::compress::decompress(&d.data)
                                    } else {
                                        d.data.to_vec()
                                    };
                                    debug_dump(&mut dlog, "IN", &data);
                                    let mut stdout = std::io::stdout();
                                    stdout.write_all(&data)?;
                                    stdout.flush()?;
                                }
                                Some(terminal_response::Union::Closed(c)) => {
                                    eprintln!("[terminal closed, exit_code={}]", c.exit_code);
                                    debug_event(&mut dlog, &format!("Closed exit_code={}", c.exit_code));
                                    break;
                                }
                                Some(terminal_response::Union::Error(e)) => {
                                    eprintln!("[terminal error: {}]", e.message);
                                    debug_event(&mut dlog, &format!("Error: {}", e.message));
                                }
                                _ => {}
                            },
                            _ => {}
                        }
                    }
                    Some(Err(e)) => {
                        eprintln!("connection error: {e}");
                        debug_event(&mut dlog, &format!("connection error: {e}"));
                        break;
                    }
                    None => {
                        debug_event(&mut dlog, "stream ended (None)");
                        break;
                    }
                }
            }
            Some(chunk) = stdin_rx.recv(), if opened => {
                debug_dump(&mut dlog, "OUT", &chunk);
                let mut td = TerminalData::new();
                td.terminal_id = 0;
                td.data = chunk.into();
                let mut action = TerminalAction::new();
                action.set_data(td);
                let mut m = Message::new();
                m.set_terminal_action(action);
                peer.send(&m).await?;
            }
            _ = winch.recv(), if opened => {
                if let Some((rows, cols)) = terminal_size() {
                    let mut resize = ResizeTerminal::new();
                    resize.terminal_id = 0;
                    resize.rows = rows;
                    resize.cols = cols;
                    let mut action = TerminalAction::new();
                    action.set_resize(resize);
                    let mut m = Message::new();
                    m.set_terminal_action(action);
                    peer.send(&m).await?;
                }
            }
        }
    }

    // Остаток очистки — через Drop у _raw_guard (см. RawModeGuard), не
    // явным вызовом здесь: этот код достигается только при обычном
    // break, а RawModeGuard страхует ещё и все остальные пути выхода.
    Ok(())
}
