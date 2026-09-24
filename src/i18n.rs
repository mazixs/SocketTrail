//! Язык окна, отчета и сообщений в консоли: английский по умолчанию, русский вторым.
//! Выбор из окна сохраняется в каталоге кеша, ключ --lang переопределяет его на запуск.

use std::sync::atomic::{AtomicBool, Ordering};

static RU: AtomicBool = AtomicBool::new(false);

pub fn ru() -> bool {
    RU.load(Ordering::Relaxed)
}

pub fn code() -> &'static str {
    if ru() { "ru" } else { "en" }
}

pub fn set(code: &str) -> bool {
    match code {
        "en" => RU.store(false, Ordering::Relaxed),
        "ru" => RU.store(true, Ordering::Relaxed),
        _ => return false,
    }
    true
}

fn file() -> std::path::PathBuf {
    crate::paths::cache_dir().join("lang")
}

pub fn load() {
    if let Ok(s) = std::fs::read_to_string(file()) {
        set(s.trim());
    }
}

pub fn save() {
    let f = file();
    if let Some(dir) = f.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(f, code());
}

/// Выбор из пары статических строк.
pub fn tr(en: &'static str, ru_text: &'static str) -> &'static str {
    if ru() { ru_text } else { en }
}

/// Текст на обоих языках: для сообщений, которые запоминаются при старте, а
/// показываются позже, возможно уже после переключения языка.
#[derive(Clone, Debug)]
pub struct Text {
    pub en: String,
    pub ru: String,
}

/// Технические сообщения (коды ошибок, вывод утилит) одинаковы на обоих языках.
impl From<String> for Text {
    fn from(s: String) -> Self {
        Text {
            en: s.clone(),
            ru: s,
        }
    }
}

impl Text {
    pub fn get(&self) -> &str {
        if ru() { &self.ru } else { &self.en }
    }
}

/// Строка на текущем языке: t!("Port {p} is busy", "Порт {p} занят").
#[macro_export]
macro_rules! t {
    ($en:literal, $ru:literal) => {
        if $crate::i18n::ru() {
            format!($ru)
        } else {
            format!($en)
        }
    };
}

/// Text на обоих языках: text!("...", "...").
#[macro_export]
macro_rules! text {
    ($en:literal, $ru:literal) => {
        $crate::i18n::Text {
            en: format!($en),
            ru: format!($ru),
        }
    };
}
