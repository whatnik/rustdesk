// Тонкая обёртка над librustdesk::headless_terminal — вся логика в
// src/headless_terminal.rs (часть библиотечного крейта, т.к. ей нужен
// доступ к приватному модулю `client`, недоступному отдельному бинарю).
//
// `librustdesk::headless_terminal` в lib.rs исключён на android/ios
// (`#[cfg(not(any(target_os = "android", target_os = "ios")))]` —
// see lib.rs) — сам бинарник там никогда не собирается и не запускается
// (только `build-headless-terminal.sh`, локально, всегда на Linux). Но
// `cargo ndk ... build` в android-only-build.yml (в отличие от `--lib` у
// windows-only-build.yml) собирает вообще все таргеты крейта, включая
// [[bin]] headless_terminal из Cargo.toml — без cfg здесь сборка Android
// падала бы с "unresolved import librustdesk::headless_terminal" (найдено
// вживую 2026-09-10). Ниже — весь реальный код под cfg + пустая заглушка
// на android/ios, чтобы `fn main()` существовал ровно один на любой
// платформе.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use librustdesk::headless_terminal::{run, HeadlessTerminalArgs};

#[cfg(any(target_os = "android", target_os = "ios"))]
fn main() {}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn print_usage_and_exit() -> ! {
    eprintln!(
        "Использование: headless_terminal --id <RUSTDESK_ID> --password <PASSWORD> \
         [--rows N] [--cols N] [--debug-log <путь>] [--check-only] \
         [--admin [--admin-user <ИМЯ>] [--admin-password <ПАРОЛЬ>]]\n\n\
         --admin           открыть терминал от имени администратора управляемой\n\
         \x20                  стороны (аналог \"Terminal (Run as administrator)\" в\n\
         \x20                  официальном клиенте) — если --admin-user/--admin-password\n\
         \x20                  не заданы явно, берутся из переменных окружения\n\
         \x20                  HEADLESS_TERMINAL_ADMIN_USER/_PASSWORD, а если и их нет —\n\
         \x20                  спрашиваются интерактивно.\n\
         --check-only      только проверить, что --password подходит этому ID —\n\
         \x20                  терминал не открывается. Успех: печатает \"AUTH_OK\",\n\
         \x20                  exit 0. Провал: exit != 0."
    );
    std::process::exit(2);
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn main() {
    // `tokio` не является прямым зависимым пакета верхнего уровня (все
    // остальные модули идут через `hbb_common::tokio`) — поэтому вместо
    // атрибута `#[tokio::main]` (который резолвит крейт `tokio` напрямую)
    // руками поднимаем рантайм через реэкспорт hbb_common.
    hbb_common::tokio::runtime::Runtime::new()
        .expect("failed to build tokio runtime")
        .block_on(async_main());
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn async_main() {
    let mut id = None;
    let mut password = None;
    let mut rows: Option<u32> = None;
    let mut cols: Option<u32> = None;
    let mut debug_log: Option<String> = None;
    let mut admin = false;
    let mut admin_user: Option<String> = None;
    let mut admin_password: Option<String> = None;
    let mut check_only = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--id" => id = args.next(),
            "--password" => password = args.next(),
            "--rows" => rows = args.next().and_then(|v| v.parse().ok()),
            "--cols" => cols = args.next().and_then(|v| v.parse().ok()),
            "--debug-log" => debug_log = args.next(),
            "--admin" => admin = true,
            "--admin-user" => admin_user = args.next(),
            "--admin-password" => admin_password = args.next(),
            "--check-only" => check_only = true,
            "-h" | "--help" => print_usage_and_exit(),
            _ => print_usage_and_exit(),
        }
    }

    let (Some(id), Some(password)) = (id, password) else {
        print_usage_and_exit();
    };

    if let Err(e) = run(HeadlessTerminalArgs {
        id,
        password,
        rows,
        cols,
        debug_log,
        admin,
        admin_user,
        admin_password,
        check_only,
    })
    .await
    {
        eprintln!("Ошибка: {e:#}");
        std::process::exit(1);
    }
}
