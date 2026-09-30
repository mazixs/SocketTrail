//! Платформенный захват: PktMon/ETW на Windows, dumpcap на Linux.

#[cfg(not(windows))]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;
