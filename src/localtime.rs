//! Местное время без внешних зависимостей: для имен файлов и подписей в отчетах.

use std::sync::OnceLock;

use crate::state::now_ms;

/// Смещение локальной зоны в секундах, снимается один раз при старте.
fn tz_offset() -> i64 {
    static OFF: OnceLock<i64> = OnceLock::new();
    *OFF.get_or_init(tz_offset_os)
}

/// Bias в минутах со знаком "UTC минус местное", плюс поправка текущего сезона.
#[cfg(windows)]
fn tz_offset_os() -> i64 {
    use windows_sys::Win32::System::Time::{
        DYNAMIC_TIME_ZONE_INFORMATION, GetDynamicTimeZoneInformation,
    };
    let mut tz: DYNAMIC_TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    let bias = match unsafe { GetDynamicTimeZoneInformation(&mut tz) } {
        1 => tz.Bias + tz.StandardBias,
        2 => tz.Bias + tz.DaylightBias,
        _ => tz.Bias,
    };
    -(bias as i64) * 60
}

#[cfg(not(windows))]
fn tz_offset_os() -> i64 {
    let out = std::process::Command::new("date").arg("+%z").output();
    let s = out
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    // формат +0300
    if s.len() == 5 {
        let sign = if s.starts_with('-') { -1 } else { 1 };
        let h: i64 = s[1..3].parse().unwrap_or(0);
        let m: i64 = s[3..5].parse().unwrap_or(0);
        sign * (h * 3600 + m * 60)
    } else {
        0
    }
}

pub fn human_time(ms: u64) -> String {
    let secs = ms as i64 / 1000 + tz_offset();
    let (y, mo, d) = civil_from_days(secs.div_euclid(86400));
    let t = secs.rem_euclid(86400);
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02}",
        t / 3600,
        (t % 3600) / 60,
        t % 60
    )
}

/// Метка вида 20260920-153045 по локальному времени.
pub fn stamp() -> String {
    let secs = now_ms() as i64 / 1000 + tz_offset();
    let tod = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(secs.div_euclid(86400));
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Алгоритм Говарда Хиннанта: число дней от эпохи -> календарная дата.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_dates_from_day_numbers() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(59), (1970, 3, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn stamp_has_a_fixed_shape_for_file_names() {
        let s = stamp();
        assert_eq!(s.len(), 15);
        assert_eq!(s.as_bytes()[8], b'-');
        assert!(
            s.bytes()
                .enumerate()
                .all(|(i, b)| i == 8 || b.is_ascii_digit())
        );
    }
}
