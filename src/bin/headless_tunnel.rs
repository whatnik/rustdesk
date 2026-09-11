// Тонкая обёртка над librustdesk::headless_tunnel — вся логика в
// src/headless_tunnel.rs (часть библиотечного крейта, т.к. ей нужен доступ к
// приватным модулям `client`/`port_forward`, недоступным отдельному бинарю).
// Структура файла — по образцу bin/headless_terminal.rs (заглушка на
// android/ios по той же причине: `cargo ndk ... build` в android-only-
// build.yml собирает все таргеты крейта, включая [[bin]] из Cargo.toml, без
// `--lib`, см. CLAUDE.md/headless_terminal.rs).
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use librustdesk::headless_tunnel::{run, ForwardSpec, SocksSpec, TunnelArgs};

#[cfg(any(target_os = "android", target_os = "ios"))]
fn main() {}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn print_usage_and_exit() -> ! {
    eprintln!(
        "Использование: headless_tunnel --id <RUSTDESK_ID> [--password <PWD>]\n\
         \x20   [-L [bind:]lport:rhost:rport]...  проброс порта (аналог ssh -L),\n\
         \x20                                     можно указывать несколько раз\n\
         \x20   [-D [bind:]port]                  локальный SOCKS5-прокси (аналог ssh -D)\n\
         \x20   [--test rhost:rport]               проверить доступность цели и выйти\n\
         \x20                                     (AUTH/доступность OK -> \"OK\", exit 0;\n\
         \x20                                     иначе текст ошибки, exit != 0)\n\
         \x20   [--allow-insecure]                продолжать, даже если сервер не\n\
         \x20                                     поддержал сквозное шифрование\n\
         \x20   [-v]                               подробный лог на stderr\n\n\
         Пароль, если не передан через --password, берётся из переменной\n\
         окружения HEADLESS_TUNNEL_PASSWORD.\n\
         bind по умолчанию 127.0.0.1; 0.0.0.0 открывает порт/прокси всей\n\
         локальной сети — указывайте осознанно.\n\n\
         Примеры:\n\
         \x20 headless_tunnel --id 123456789 -L 2222:localhost:22\n\
         \x20 headless_tunnel --id 123456789 -D 1080\n\
         \x20 headless_tunnel --id 123456789 --test localhost:3389"
    );
    std::process::exit(2);
}

/// Разбивает строку по `:`, не трогая содержимое `[...]` (для IPv6-литералов
/// в bind/rhost) — `"127.0.0.1:2222:localhost:22"` -> 4 части,
/// `"[::1]:2222:localhost:22"` -> тоже 4 части (`[::1]` не режется).
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn split_colon_aware(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_brackets = false;
    for ch in s.chars() {
        match ch {
            '[' => {
                in_brackets = true;
                cur.push(ch);
            }
            ']' => {
                in_brackets = false;
                cur.push(ch);
            }
            ':' if !in_brackets => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    parts.push(cur);
    parts
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn strip_brackets(s: &str) -> String {
    s.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(s)
        .to_string()
}

/// `[bind:]lport:rhost:rport` — 3 части (bind по умолчанию 127.0.0.1) или 4.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn parse_forward_spec(s: &str) -> Option<ForwardSpec> {
    let parts = split_colon_aware(s);
    let (bind, lport, rhost, rport) = match parts.as_slice() {
        [lport, rhost, rport] => ("127.0.0.1".to_string(), lport, rhost, rport),
        [bind, lport, rhost, rport] => (bind.clone(), lport, rhost, rport),
        _ => return None,
    };
    Some(ForwardSpec {
        bind: strip_brackets(&bind),
        lport: lport.parse().ok()?,
        rhost: strip_brackets(rhost),
        rport: rport.parse().ok()?,
    })
}

/// `[bind:]port` — 1 часть (bind по умолчанию 127.0.0.1) или 2.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn parse_socks_spec(s: &str) -> Option<SocksSpec> {
    let parts = split_colon_aware(s);
    let (bind, port) = match parts.as_slice() {
        [port] => ("127.0.0.1".to_string(), port),
        [bind, port] => (bind.clone(), port),
        _ => return None,
    };
    Some(SocksSpec {
        bind: strip_brackets(&bind),
        port: port.parse().ok()?,
    })
}

/// `rhost:rport` для `--test`.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn parse_host_port(s: &str) -> Option<(String, u16)> {
    let parts = split_colon_aware(s);
    match parts.as_slice() {
        [host, port] => Some((strip_brackets(host), port.parse().ok()?)),
        _ => None,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn main() {
    // `tokio` не является прямым зависимым пакета верхнего уровня (см. тот
    // же приём в bin/headless_terminal.rs) — рантайм поднимаем через
    // реэкспорт hbb_common, не через #[tokio::main].
    hbb_common::tokio::runtime::Runtime::new()
        .expect("failed to build tokio runtime")
        .block_on(async_main());
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn async_main() {
    let mut id = None;
    let mut password = None;
    let mut forwards = Vec::new();
    let mut socks = Vec::new();
    let mut test: Option<(String, u16)> = None;
    let mut allow_insecure = false;
    let mut verbose = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--id" => id = args.next(),
            "--password" => password = args.next(),
            "-L" => match args.next().as_deref().and_then(parse_forward_spec) {
                Some(spec) => forwards.push(spec),
                None => {
                    eprintln!("некорректный -L (ожидается [bind:]lport:rhost:rport)\n");
                    print_usage_and_exit();
                }
            },
            "-D" => match args.next().as_deref().and_then(parse_socks_spec) {
                Some(spec) => socks.push(spec),
                None => {
                    eprintln!("некорректный -D (ожидается [bind:]port)\n");
                    print_usage_and_exit();
                }
            },
            "--test" => match args.next().as_deref().and_then(parse_host_port) {
                Some(v) => test = Some(v),
                None => {
                    eprintln!("некорректный --test (ожидается rhost:rport)\n");
                    print_usage_and_exit();
                }
            },
            "--allow-insecure" => allow_insecure = true,
            "-v" | "--verbose" => verbose = true,
            "-h" | "--help" => print_usage_and_exit(),
            other => {
                eprintln!("неизвестный аргумент: {other}\n");
                print_usage_and_exit();
            }
        }
    }

    let Some(id) = id else {
        print_usage_and_exit();
    };
    let password = password
        .or_else(|| std::env::var("HEADLESS_TUNNEL_PASSWORD").ok())
        .unwrap_or_default();
    if password.is_empty() {
        eprintln!("предупреждение: пароль не задан (--password / HEADLESS_TUNNEL_PASSWORD пусты)");
    }

    if test.is_some() && (!forwards.is_empty() || !socks.is_empty()) {
        eprintln!("--test нельзя сочетать с -L/-D — это разовая проверка, не запуск туннеля\n");
        print_usage_and_exit();
    }
    if forwards.is_empty() && socks.is_empty() && test.is_none() {
        print_usage_and_exit();
    }

    let args = TunnelArgs {
        id,
        password,
        forwards,
        socks,
        test: test.map(|(h, p)| (h, p as i32)),
        allow_insecure,
        verbose,
    };

    if let Err(e) = run(args).await {
        eprintln!("Ошибка: {e:#}");
        std::process::exit(1);
    }
}
