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
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn run(bin: &str, args: &[&str]) -> Option<(String, String, bool)> {
    let fut = Command::new(bin).args(args).output();
    let out = tokio::time::timeout(CALL_TIMEOUT, fut).await.ok()?.ok()?;
    Some((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    ))
}

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
