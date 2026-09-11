// Headless (no GUI/Flutter) клиент проброса портов через RustDesk
// (ConnType::PORT_FORWARD) — консольный аналог `ssh -L`/`ssh -D`. Второй
// модуль в том же семействе, что headless_terminal.rs (см. его докстринг
// для общего объяснения подхода: тот же сетевой/протокольный путь
// `client::Client::start`/`client::Interface`, без единой строчки GUI).
//
// В отличие от терминала, у port forward нет собственного протокола поверх
// логина — после успешной авторизации обе стороны (`Stream::set_raw()`,
// hbb_common/src/tcp.rs) выбрасывают protobuf-обёртку и шифрование сессии и
// просто гоняют сырые TCP-байты. Всю эту механику уже реализует апстримный
// `src/port_forward.rs` (`connect_and_login`/`run_forward`) — мы его не
// копируем, а переиспользуем напрямую (см. build-headless-tunnel.sh: эти
// две функции патчатся с приватных на `pub(crate)`).
//
// Апстримный `port_forward::listen()` не годится как есть — он жёстко
// биндит 127.0.0.1, трактует port==0 как запуск локального RDP-клиента
// (mstsc) и держит ОДИН `LoginConfigHandler` на все параллельные
// соединения. Последнее — не просто неудобство: `LoginConfigHandler.
// port_forward` (host, port) читается уже ПОСЛЕ Client::start(), в момент
// формирования LoginRequest (после того как пришёл Hash от сервера) — при
// общем lc два параллельных соединения гонялись бы за то, чей host:port
// реально уйдёт на провод. Поэтому здесь — свой accept-цикл, свой
// LoginConfigHandler (и своя пара Interface/канал) на КАЖДОЕ входящее
// TCP-соединение.

use async_trait::async_trait;
use crate::client::{Data, Interface, LoginConfigHandler};
use crate::port_forward::{connect_and_login, run_forward};
use hbb_common::{
    bail,
    config::LocalConfig,
    message_proto::{self, *},
    rendezvous_proto::ConnType,
    tcp,
    tokio::{
        self,
        net::{TcpListener, TcpStream},
        sync::mpsc,
    },
    tokio_util::codec::{BytesCodec, Framed},
    ResultType, Stream,
};
use std::sync::{Arc, Mutex, RwLock};

/// Проброс `-L`: `bind:lport` слушается локально, каждое новое соединение
/// на нём открывает отдельную RustDesk-сессию к `rhost:rport` на управляемой
/// машине.
pub struct ForwardSpec {
    pub bind: String,
    pub lport: u16,
    pub rhost: String,
    pub rport: u16,
}

/// `-D`: локальный SOCKS5-listener (аналог `ssh -D`) — цель узнаётся из
/// SOCKS-запроса каждого отдельного соединения, а не из аргументов CLI.
pub struct SocksSpec {
    pub bind: String,
    pub port: u16,
}

pub struct TunnelArgs {
    pub id: String,
    pub password: String,
    pub forwards: Vec<ForwardSpec>,
    pub socks: Vec<SocksSpec>,
    /// `--test rhost:rport` — один разовый прогон логина без настоящего
    /// локального клиента на другом конце, см. `test_target()`.
    pub test: Option<(String, i32)>,
    /// Не отклонять автоматически незашифрованное соединение (сервер не
    /// поддержал E2E) — по умолчанию отклоняем, т.к. после set_raw()
    /// шифрования сессии больше нет вообще (см. докстринг выше), и молча
    /// продолжать небезопасно.
    pub allow_insecure: bool,
    pub verbose: bool,
}

/// `Interface` для проброса портов — по структуре копия `HeadlessInterface`
/// из headless_terminal.rs, с двумя отличиями, специфичными для port
/// forward:
///   - `msgbox()` обрабатывает `insecure-connection-*` (шлётся из
///     `client::confirm_insecure_connection()`, `src/client.rs`, когда
///     сервер не поддержал E2E-шифрование) — без ответа в канал эта функция
///     ждёт вечно;
///   - `handle_login_error()`/`msgbox()` сохраняют текст последней ошибки
///     в `last_error`, чтобы вызывающий код (SOCKS-reply, `--test`) мог его
///     показать — `connect_and_login()` в обоих случаях (отказ от
///     небезопасного соединения и ошибка логина) возвращает одно и то же
///     `Ok(None)`, не давая различить причину иначе.
#[derive(Clone)]
struct TunnelInterface {
    lc: Arc<RwLock<LoginConfigHandler>>,
    tx: mpsc::UnboundedSender<Data>,
    allow_insecure: bool,
    last_error: Arc<Mutex<Option<String>>>,
    verbose: bool,
}

#[async_trait]
impl Interface for TunnelInterface {
    fn send(&self, _data: Data) {}

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, _link: &str) {
        if msgtype.starts_with("insecure-connection") {
            if self.allow_insecure {
                let _ = self.tx.send(Data::ContinueInsecureConnection);
            } else {
                *self.last_error.lock().unwrap() = Some(
                    "сервер не поддержал сквозное шифрование — соединение отклонено \
                     (используйте --allow-insecure, если это ожидаемо)"
                        .to_string(),
                );
                let _ = self.tx.send(Data::RejectInsecureConnection);
            }
            return;
        }
        if self.verbose {
            eprintln!("[{msgtype}] {title}: {text}");
        }
    }

    fn handle_login_error(&self, err: &str) -> bool {
        *self.last_error.lock().unwrap() = Some(err.to_string());
        eprintln!("login error: {err}");
        false
    }

    fn handle_peer_info(&self, pi: message_proto::PeerInfo) {
        if self.verbose {
            eprintln!(
                "[connected] hostname={} platform={} version={}",
                pi.hostname, pi.platform, pi.version
            );
        }
    }

    fn set_multiple_windows_session(&self, _sessions: Vec<WindowsSession>) {}

    async fn handle_hash(&self, pass: &str, hash: message_proto::Hash, peer: &mut Stream) {
        crate::client::handle_hash(self.lc.clone(), pass, hash, self, peer).await;
    }

    async fn handle_login_from_ui(
        &self,
        _os_username: String,
        _os_password: String,
        _password: String,
        _remember: bool,
        _peer: &mut Stream,
    ) {
        // Проброс портов не использует admin-OSLogin (это только у
        // Terminal, см. headless_terminal.rs) и не переспрашивает пароль
        // через UI — сюда этот путь в принципе не попадает.
    }

    async fn handle_test_delay(&self, _t: message_proto::TestDelay, _peer: &mut Stream) {}

    fn get_lch(&self) -> Arc<RwLock<LoginConfigHandler>> {
        self.lc.clone()
    }
}

/// Полный цикл одной сессии: свой `LoginConfigHandler`, логин через
/// апстримный `connect_and_login()`, возврат "сырого" `Stream` к
/// управляемой машине, готового к пробросу через `run_forward()`.
///
/// `forward` — уже принятое локальное соединение (или его суррогат для
/// `--test`, см. `dummy_tcp_pair()`). `connect_and_login()` держит на него
/// `&mut`-ссылку только на время логина (буферизует байты, которые локальный
/// клиент успел прислать ДО завершения логина) — после успеха возвращает
/// владение обратно вызывающему через сам `forward`, не поглощая его.
///
/// Канал `tx`/`rx` создаётся и живёт здесь же: `connect_and_login()` внутри
/// `tokio::select!` читает `ui_receiver.recv()` — если все `tx` дропнуты
/// раньше времени, `recv()` начинает мгновенно возвращать `None` и цикл
/// логина превращается в busy-loop на 100% CPU. `iface` (владеющий `tx`)
/// живёт до конца этой функции, поэтому такого не происходит.
async fn open_session(
    id: &str,
    password: &str,
    key: &str,
    token: &str,
    host: String,
    port: i32,
    forward: &mut Framed<TcpStream, BytesCodec>,
    allow_insecure: bool,
    verbose: bool,
) -> ResultType<Stream> {
    let lc = Arc::new(RwLock::new(LoginConfigHandler::default()));
    lc.write().unwrap().initialize(
        id.to_owned(),
        ConnType::PORT_FORWARD,
        None,
        false,
        None,
        None,
        None,
    );
    lc.write().unwrap().port_forward = (host.clone(), port);

    let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
    let last_error = Arc::new(Mutex::new(None));
    let iface = TunnelInterface {
        lc,
        tx,
        allow_insecure,
        last_error: last_error.clone(),
        verbose,
    };

    let mut close_port_forward = false;
    let result = connect_and_login(
        id,
        password,
        &mut rx,
        iface.clone(),
        forward,
        key,
        token,
        false, // is_rdp — никогда: RDP-режим апстрима сам запускает mstsc, нам это не нужно
        &mut close_port_forward,
    )
    .await;

    match result {
        Ok(Some(stream)) => Ok(stream),
        Ok(None) => {
            let msg = last_error
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| "соединение отклонено сервером".to_string());
            bail!("{msg}");
        }
        Err(e) => Err(e),
    }
}

/// Пара реально соединённых loopback-сокетов для `--test`: обе половины
/// держатся живыми и молчат (ничего не шлют, не закрываются) до конца
/// вызова — иначе `connect_and_login()`, у которого в `tokio::select!` есть
/// ветка `res = forward.next() => { ... else { return Ok(None) } }`, увидит
/// EOF на "локальном" конце раньше, чем придёт настоящий ответ сервера, и
/// ошибочно завершится, как будто отменено пользователем.
async fn dummy_tcp_pair() -> ResultType<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let connect_task = tokio::spawn(async move { TcpStream::connect(addr).await });
    let (accepted, _) = listener.accept().await?;
    let connecting = connect_task.await??;
    Ok((connecting, accepted))
}

/// `--test rhost:rport` — довести логин до `LoginResponse` и сразу выйти, не
/// открывая реальный проброс (аналог `--check-only` у headless_terminal, но
/// проверяет не пароль как таковой, а доступность конкретной цели с точки
/// зрения управляемой машины: право `enable-tunnel`/`tunnel` и то, что
/// `rhost:rport` там вообще что-то слушает — `connection.rs::
/// connect_port_forward_if_needed` на управляемой стороне сама делает
/// `TcpStream::connect` и возвращает "Failed to access remote ..." при
/// неудаче).
async fn test_target(
    id: &str,
    password: &str,
    key: &str,
    token: &str,
    host: String,
    port: i32,
    allow_insecure: bool,
    verbose: bool,
) -> ResultType<()> {
    let (local, _keep_alive) = dummy_tcp_pair().await?;
    let mut forward = Framed::new(local, BytesCodec::new());
    open_session(
        id,
        password,
        key,
        token,
        host,
        port,
        &mut forward,
        allow_insecure,
        verbose,
    )
    .await?;
    println!("OK");
    Ok(())
}

async fn serve_forward(
    listener: TcpListener,
    id: String,
    password: String,
    key: String,
    token: String,
    rhost: String,
    rport: u16,
    allow_insecure: bool,
    verbose: bool,
) {
    loop {
        let (sock, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[-L {rhost}:{rport}] accept error: {e}");
                continue;
            }
        };
        if verbose {
            eprintln!("[-L {rhost}:{rport}] новое соединение от {peer_addr}");
        }
        let (id, password, key, token, rhost_c) =
            (id.clone(), password.clone(), key.clone(), token.clone(), rhost.clone());
        let rport_i = rport as i32;
        tokio::spawn(async move {
            let mut forward = Framed::new(sock, BytesCodec::new());
            match open_session(
                &id,
                &password,
                &key,
                &token,
                rhost_c.clone(),
                rport_i,
                &mut forward,
                allow_insecure,
                verbose,
            )
            .await
            {
                Ok(stream) => {
                    if let Err(e) = run_forward(forward, stream).await {
                        if verbose {
                            eprintln!("[-L {rhost_c}:{rport_i}] {peer_addr}: ошибка проброса: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[-L {rhost_c}:{rport_i}] {peer_addr}: не удалось подключиться: {e}"
                    );
                }
            }
            if verbose {
                eprintln!("[-L {rhost_c}:{rport_i}] {peer_addr} закрыто");
            }
        });
    }
}

/// Минимальный SOCKS5 (RFC 1928): без аутентификации, только `CONNECT`
/// (ATYP 1/3/4 — IPv4/домен/IPv6). Домен передаётся на управляемую сторону
/// как есть, не резолвится локально — DNS реально происходит на ней
/// (`TcpStream::connect(&addr)`, `server/connection.rs::
/// connect_port_forward_if_needed`), то есть remote-DNS работает "бесплатно",
/// без отдельной реализации на нашей стороне. `BIND`/`UDP ASSOCIATE`
/// отклоняются (`0x07`) — RustDesk Port Forward умеет только TCP.
async fn handle_socks_conn(
    mut sock: TcpStream,
    id: &str,
    password: &str,
    key: &str,
    token: &str,
    allow_insecure: bool,
    verbose: bool,
) -> ResultType<()> {
    use hbb_common::tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Greeting: VER(1)=5, NMETHODS(1), METHODS(NMETHODS) — отвечаем "без
    // аутентификации" безусловно, других методов не предлагаем.
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        bail!("неподдерживаемая версия SOCKS: {}", hdr[0]);
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[0x05, 0x00]).await?;

    // Request: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR DST.PORT(2)
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    let (ver, cmd, atyp) = (req[0], req[1], req[3]);
    if ver != 0x05 {
        bail!("неподдерживаемая версия SOCKS: {ver}");
    }

    let host = match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x03 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            sock.read_exact(&mut d).await?;
            String::from_utf8(d).map_err(|_| hbb_common::anyhow::anyhow!("некорректный домен в SOCKS-запросе"))?
        }
        0x04 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => {
            let _ = sock
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await; // address type not supported
            bail!("неподдерживаемый ATYP {atyp}");
        }
    };
    let mut portb = [0u8; 2];
    sock.read_exact(&mut portb).await?;
    let port = u16::from_be_bytes(portb) as i32;

    if cmd != 0x01 {
        let _ = sock
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await; // command not supported — только CONNECT
        bail!("неподдерживаемая SOCKS-команда {cmd} (поддерживается только CONNECT)");
    }

    if verbose {
        eprintln!("[-D] CONNECT {host}:{port}");
    }

    let mut forward = Framed::new(sock, BytesCodec::new());
    match open_session(id, password, key, token, host.clone(), port, &mut forward, allow_insecure, verbose).await {
        Ok(stream) => {
            forward
                .get_mut()
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            if let Err(e) = run_forward(forward, stream).await {
                if verbose {
                    eprintln!("[-D] {host}:{port}: ошибка проброса: {e}");
                }
            }
            Ok(())
        }
        Err(e) => {
            let _ = forward
                .get_mut()
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await; // connection refused
            Err(e)
        }
    }
}

async fn serve_socks(
    listener: TcpListener,
    id: String,
    password: String,
    key: String,
    token: String,
    allow_insecure: bool,
    verbose: bool,
) {
    loop {
        let (sock, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[-D] accept error: {e}");
                continue;
            }
        };
        let (id, password, key, token) = (id.clone(), password.clone(), key.clone(), token.clone());
        tokio::spawn(async move {
            if let Err(e) =
                handle_socks_conn(sock, &id, &password, &key, &token, allow_insecure, verbose).await
            {
                eprintln!("[-D] {peer_addr}: {e}");
            }
        });
    }
}

pub async fn run(args: TunnelArgs) -> ResultType<()> {
    // Тот же приём, что в headless_terminal.rs — без явного init_log()
    // весь log::info!/warn! по client.rs/hbb_common молча уходит в никуда.
    let _log_handle = hbb_common::init_log(false, "headless_tunnel");

    if !crate::common::global_init() {
        bail!("global_init failed");
    }

    let key = crate::get_key(false).await;
    let token = LocalConfig::get_option("access_token");

    if let Some((host, port)) = args.test {
        return test_target(
            &args.id,
            &args.password,
            &key,
            &token,
            host,
            port,
            args.allow_insecure,
            args.verbose,
        )
        .await;
    }

    // Слушатели биндятся ЗДЕСЬ, до spawn — чтобы ошибка вида "порт уже
    // занят" была видна сразу как ошибка run(), а не терялась в фоновой
    // задаче.
    enum Job {
        Forward(TcpListener, String, u16),
        Socks(TcpListener),
    }
    let mut jobs = Vec::new();
    for spec in &args.forwards {
        let addr = format!("{}:{}", spec.bind, spec.lport);
        let listener = tcp::new_listener(addr.clone(), true)
            .await
            .map_err(|e| hbb_common::anyhow::anyhow!("не удалось слушать {addr}: {e}"))?;
        eprintln!("[-L] {addr} -> {}:{} (id {})", spec.rhost, spec.rport, args.id);
        jobs.push(Job::Forward(listener, spec.rhost.clone(), spec.rport));
    }
    for spec in &args.socks {
        let addr = format!("{}:{}", spec.bind, spec.port);
        let listener = tcp::new_listener(addr.clone(), true)
            .await
            .map_err(|e| hbb_common::anyhow::anyhow!("не удалось слушать {addr}: {e}"))?;
        eprintln!("[-D] SOCKS5 на {addr} (id {})", args.id);
        jobs.push(Job::Socks(listener));
    }

    for job in jobs {
        let (id, password, key, token) = (args.id.clone(), args.password.clone(), key.clone(), token.clone());
        let allow_insecure = args.allow_insecure;
        let verbose = args.verbose;
        match job {
            Job::Forward(listener, rhost, rport) => {
                tokio::spawn(serve_forward(
                    listener,
                    id,
                    password,
                    key,
                    token,
                    rhost,
                    rport,
                    allow_insecure,
                    verbose,
                ));
            }
            Job::Socks(listener) => {
                tokio::spawn(serve_socks(listener, id, password, key, token, allow_insecure, verbose));
            }
        }
    }

    eprintln!("Готово, ожидаю подключений (Ctrl-C для выхода)...");
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("Останавливаюсь...");
    Ok(())
}
