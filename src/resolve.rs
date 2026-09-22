//! Опознание владельца адреса. PTR и ASN расходятся гораздо чаще, чем кажется:
//! сеть 193.202.112.0/24 по RDAP записана на ирландского хостера, а анонсирует
//! ее AS13335 Cloudflare. Поэтому показываем оба источника, а не один.
//!
//! Спрашиваем через resolvectl, а dig оставлен запасным путем. Разница не
//! косметическая: systemd-resolved держит DNS отдельно на каждом сетевом
//! интерфейсе, и обратные зоны провайдера видны только через него. Один и тот
//! же адрес dig отдавал то с именем, то без - отсюда и брались соседние строки
//! таблицы, где у одних адресов домен есть, а у других нет:
//!
//!   $ dig +short -x 192.0.2.35              -> пусто
//!   $ resolvectl query 192.0.2.35           -> 192-0-2-35.dynamic.example-isp.net

use std::net::IpAddr;

#[cfg(not(windows))]
use tokio::process::Command;

#[derive(Clone, Default)]
pub struct Whois {
    pub ptr: Option<String>,
    pub asn: Option<String>,
    pub owner: Option<String>,
    /// Резолвер не ответил (таймаут, SERVFAIL, отказ). Такой результат нельзя
    /// считать окончательным: адрес остался бы без имени до перезапуска, хотя
    /// имя у него есть, - поэтому к нему возвращаемся позже.
    pub failed: bool,
}

enum Answer {
    Ok(String),
    /// Ответ пришел, записи нет - повторять бессмысленно.
    Empty,
    /// Ответа не было.
    Failed,
}

/// Отсев всего, что не похоже на доменное имя: в колонку домена должны
/// попадать только имена, а не диагностика резолвера.
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && !s.contains(' ')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

#[cfg(not(windows))]
fn have_resolvectl() -> bool {
    use std::sync::OnceLock;
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        std::process::Command::new("resolvectl")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// Верхняя граница на один запрос. Без нее зависший резолвер останавливает
/// всю очередь опознания, и адреса остаются безымянными неограниченно долго.
#[cfg(not(windows))]
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(not(windows))]
async fn run(bin: &str, args: &[&str]) -> Option<(String, String, bool)> {
    let fut = Command::new(bin).args(args).output();
    let out = tokio::time::timeout(CALL_TIMEOUT, fut).await.ok()?.ok()?;
    Some((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    ))
}

#[cfg(not(windows))]
/// PTR через resolvectl: "192.0.2.35: 192-0-2-35.dynamic.example-isp.net -- link: eth0"
async fn ptr_resolvectl(ip: &IpAddr) -> Answer {
    let Some((out, err, _)) = run("resolvectl", &["query", "--legend=no", &ip.to_string()]).await
    else {
        return Answer::Failed;
    };
    let both = format!("{out}{err}");
    if both.contains("not found") {
        return Answer::Empty;
    }
    for line in out.lines() {
        let Some((head, rest)) = line.split_once(": ") else {
            continue;
        };
        if head.trim() != ip.to_string() {
            continue;
        }
        let name = rest
            .split(" -- ")
            .next()
            .unwrap_or("")
            .trim()
            .trim_end_matches('.');
        if valid_name(name) {
            return Answer::Ok(name.to_string());
        }
    }
    Answer::Failed
}

#[cfg(not(windows))]
/// TXT через resolvectl: `name IN TXT "13335 | 104.16.0.0/12 | US | arin | ..."`
async fn txt_resolvectl(name: &str) -> Answer {
    let Some((out, err, _)) =
        run("resolvectl", &["query", "--legend=no", "--type=TXT", name]).await
    else {
        return Answer::Failed;
    };
    if format!("{out}{err}").contains("not found") {
        return Answer::Empty;
    }
    for line in out.lines() {
        if let Some(start) = line.find('"')
            && let Some(end) = line[start + 1..].find('"')
        {
            return Answer::Ok(line[start + 1..start + 1 + end].to_string());
        }
    }
    Answer::Failed
}

#[cfg(not(windows))]
/// Запасной путь для систем без systemd-resolved. Диагностику dig печатает
/// в stdout вперемешку с ответом, поэтому строки с ';' отбрасываем.
async fn dig_short(args: &[&str]) -> Answer {
    let mut full = vec!["+short", "+time=3", "+tries=2"];
    full.extend_from_slice(args);
    let Some((out, err, ok)) = run("dig", &full).await else {
        return Answer::Failed;
    };
    let noisy = out.lines().chain(err.lines()).any(|l| {
        let l = l.trim();
        l.starts_with(";; communications error")
            || l.starts_with(";; connection timed out")
            || l.starts_with(";; no servers could be reached")
            || l.starts_with("dig:")
    });
    for line in out.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with(';') {
            continue;
        }
        return Answer::Ok(l.trim_matches('"').to_string());
    }
    if noisy || !ok {
        Answer::Failed
    } else {
        Answer::Empty
    }
}

#[cfg(not(windows))]
async fn ptr(ip: &IpAddr) -> Answer {
    if have_resolvectl() {
        match ptr_resolvectl(ip).await {
            Answer::Failed => {}
            other => return other,
        }
    }
    match dig_short(&["-x", &ip.to_string()]).await {
        Answer::Ok(s) => {
            let s = s.trim_end_matches('.').to_string();
            if valid_name(&s) {
                Answer::Ok(s)
            } else {
                Answer::Empty
            }
        }
        other => other,
    }
}

#[cfg(not(windows))]
async fn txt(name: &str) -> Answer {
    if have_resolvectl() {
        match txt_resolvectl(name).await {
            Answer::Failed => {}
            other => return other,
        }
    }
    dig_short(&["TXT", name]).await
}

fn reverse_name(ip: &IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0]))
        }
        IpAddr::V6(_) => None, // origin6 у cymru отдельный, для первой версии не нужен
    }
}

/// Windows: системный резолвер (DnsQuery_W) учитывает DNS каждого адаптера,
/// как resolvectl на Linux. Вызов блокирующий - уводим его в пул потоков.
#[cfg(windows)]
mod win {
    use super::Answer;
    use windows_sys::Win32::Foundation::DNS_ERROR_RCODE_NAME_ERROR;
    use windows_sys::Win32::NetworkManagement::Dns::{
        DNS_QUERY_STANDARD, DNS_RECORDW, DNS_TYPE_PTR, DNS_TYPE_TEXT, DnsFree, DnsFreeRecordList,
        DnsQuery_W,
    };

    const DNS_INFO_NO_RECORDS: u32 = 9501;

    unsafe fn wstr(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        while unsafe { *p.add(n) } != 0 {
            n += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
    }

    fn query(name: &str, ty: u16) -> Answer {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut res: *mut DNS_RECORDW = std::ptr::null_mut();
        let rc = unsafe {
            DnsQuery_W(
                wide.as_ptr(),
                ty,
                DNS_QUERY_STANDARD,
                std::ptr::null_mut(),
                (&mut res as *mut *mut DNS_RECORDW).cast(),
                std::ptr::null_mut(),
            )
        };
        if rc == DNS_ERROR_RCODE_NAME_ERROR || rc == DNS_INFO_NO_RECORDS {
            return Answer::Empty;
        }
        if rc != 0 {
            return Answer::Failed;
        }
        let mut out = Answer::Empty;
        let mut r = res;
        while !r.is_null() {
            let rec = unsafe { &*r };
            if rec.wType == ty {
                let v = unsafe {
                    if ty == DNS_TYPE_PTR {
                        wstr(rec.Data.PTR.pNameHost)
                    } else {
                        let t = &rec.Data.TXT;
                        let arr = t.pStringArray.as_ptr();
                        (0..t.dwStringCount as usize).map(|i| wstr(*arr.add(i))).collect()
                    }
                };
                if !v.is_empty() {
                    out = Answer::Ok(v);
                    break;
                }
            }
            r = rec.pNext;
        }
        if !res.is_null() {
            unsafe { DnsFree(res.cast(), DnsFreeRecordList) };
        }
        out
    }

    async fn blocking(name: String, ty: u16) -> Answer {
        let job = tokio::task::spawn_blocking(move || query(&name, ty));
        match tokio::time::timeout(std::time::Duration::from_secs(5), job).await {
            Ok(Ok(a)) => a,
            _ => Answer::Failed,
        }
    }

    pub async fn ptr(name: String) -> Answer {
        blocking(name, DNS_TYPE_PTR).await
    }

    pub async fn txt(name: String) -> Answer {
        blocking(name, DNS_TYPE_TEXT).await
    }
}

/// Имя обратной зоны: 4.3.2.1.in-addr.arpa, для IPv6 - полубайты в ip6.arpa.
#[cfg(windows)]
fn arpa(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{}.in-addr.arpa", reverse_name(ip).unwrap_or_else(|| v4.to_string())),
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for b in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xF, b >> 4));
            }
            s + "ip6.arpa"
        }
    }
}

#[cfg(windows)]
async fn ptr(ip: &IpAddr) -> Answer {
    match win::ptr(arpa(ip)).await {
        Answer::Ok(s) => {
            let s = s.trim_end_matches('.').to_string();
            if valid_name(&s) { Answer::Ok(s) } else { Answer::Empty }
        }
        other => other,
    }
}

#[cfg(windows)]
async fn txt(name: &str) -> Answer {
    win::txt(name.to_string()).await
}

pub async fn lookup(ip: IpAddr) -> Whois {
    let mut w = Whois::default();

    match ptr(&ip).await {
        Answer::Ok(name) => w.ptr = Some(name),
        Answer::Empty => {}
        Answer::Failed => w.failed = true,
    }

    if let Some(rev) = reverse_name(&ip) {
        // Ответ вида: "13335 | 193.202.112.0/24 | US | arin | 2010-07-30"
        match txt(&format!("{rev}.origin.asn.cymru.com")).await {
            Answer::Ok(line) => {
                let num = line
                    .split('|')
                    .next()
                    .map(|s| s.trim().to_string())
                    .filter(|a| !a.is_empty() && a.chars().all(|c| c.is_ascii_digit()));
                if let Some(a) = num {
                    w.asn = Some(format!("AS{a}"));
                    // Название сети: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc."
                    match txt(&format!("AS{a}.asn.cymru.com")).await {
                        Answer::Ok(line) => {
                            w.owner = line
                                .split('|')
                                .next_back()
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty());
                        }
                        Answer::Empty => {}
                        Answer::Failed => w.failed = true,
                    }
                }
            }
            Answer::Empty => {}
            Answer::Failed => w.failed = true,
        }
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Нужна сеть: cargo test -- --ignored. Под Wine 10 не проходит: DnsQuery_W
    /// падает с кодом 8 на копировании EDNS-записи OPT, на Windows это не так.
    #[tokio::test]
    #[ignore]
    async fn resolves_cloudflare() {
        let w = lookup("1.1.1.1".parse().unwrap()).await;
        assert_eq!(w.ptr.as_deref(), Some("one.one.one.one"));
        assert_eq!(w.asn.as_deref(), Some("AS13335"));
        assert!(w.owner.unwrap_or_default().contains("CLOUDFLARE"));
    }
}
