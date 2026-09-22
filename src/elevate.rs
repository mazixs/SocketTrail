//! Windows: права администратора и перезапуск с ними (запрос UAC).

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut e as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && e.TokenIsElevated != 0
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Запуск себя же с правами администратора. Ok - пользователь подтвердил UAC.
pub fn relaunch(args: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let file = wide(&exe.display().to_string());
    let params = wide(args);
    let verb = wide("runas");
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = 1; // SW_SHOWNORMAL: консоль с журналом видна, как при обычном запуске
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(1223) {
            "запуск от администратора отменен".into()
        } else {
            e.to_string()
        });
    }
    Ok(())
}

/// Ожидание выхода прежнего экземпляра, чтобы занять его порт.
pub fn wait_pid(pid: u32, secs: u32) {
    unsafe {
        let h = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if h.is_null() {
            return;
        }
        let rc = WaitForSingleObject(h, secs * 1000);
        if rc == WAIT_TIMEOUT {
            eprintln!("[запуск] прежний экземпляр {pid} не завершился за {secs} с");
        }
        CloseHandle(h);
    }
}
