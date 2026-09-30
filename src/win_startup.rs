//! Оконный запуск без консоли. Терминал используется только для явного CLI-запуска.

use std::fs::{File, OpenOptions};
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Console::{
    ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    SetStdHandle,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

static TERMINAL: AtomicBool = AtomicBool::new(false);

fn message(text: &str, flags: u32) {
    let text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let title: Vec<u16> = "SocketTrail".encode_utf16().chain(Some(0)).collect();
    unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), flags) };
}

fn valid_output() -> bool {
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    !handle.is_null() && handle != INVALID_HANDLE_VALUE
}

fn cli_requested(argv: &[String]) -> bool {
    argv.iter().any(|a| a == "--help" || a == "-h")
        || (argv.iter().any(|a| a == "--no-open") && !argv.iter().any(|a| a == "--adopt"))
}

/// File живет до выхода: стандартные handles не должны указывать на закрытый файл.
pub fn init() -> Option<File> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cli = cli_requested(&argv);
    if cli {
        // Сохраняем перенаправление в pipe/file. Новую консоль никогда не создаем.
        if !valid_output() {
            unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
        }
        if valid_output() {
            TERMINAL.store(true, Ordering::Relaxed);
            return None;
        }
    }
    let dir = crate::paths::cache_dir();
    let result = (|| -> std::io::Result<File> {
        std::fs::create_dir_all(&dir)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("sockettrail.log"))?;
        // SetStdHandle меняет только таблицу процесса, а не владение File.
        for stream in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            if unsafe { SetStdHandle(stream, file.as_raw_handle()) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(file)
    })();
    match result {
        Ok(file) => {
            eprintln!("\n[SocketTrail] pid={} start", std::process::id());
            Some(file)
        }
        Err(e) => {
            message(
                &t!(
                    "Cannot open the application log: {e}",
                    "Не удалось открыть журнал приложения: {e}"
                ),
                MB_OK | MB_ICONERROR,
            );
            std::process::exit(1);
        }
    }
}

pub fn help(text: &str) {
    if TERMINAL.load(Ordering::Relaxed) {
        print!("{text}");
    } else {
        message(text, MB_OK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrator_restart_never_attaches_to_parent_console() {
        let args = ["--no-open", "--adopt", "--wait-pid", "42"].map(String::from);
        assert!(!cli_requested(&args));
        assert!(!cli_requested(&[]));
        assert!(cli_requested(&["--no-open".into()]));
        assert!(cli_requested(&["--help".into()]));
    }
}
