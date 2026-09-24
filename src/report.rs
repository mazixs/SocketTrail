//! Автономный HTML-отчет: открывается без интернета, все стили внутри файла.

use crate::i18n::tr;
use crate::state::Conn;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn bytes(n: u64) -> String {
    if n == 0 {
        "-".into()
    } else if n < 1024 {
        format!("{n} {}", tr("B", "Б"))
    } else if n < 1_048_576 {
        format!("{:.1} {}", n as f64 / 1024.0, tr("KB", "КБ"))
    } else {
        format!("{:.2} {}", n as f64 / 1_048_576.0, tr("MB", "МБ"))
    }
}

pub fn render(title: &str, generated: &str, conns: &[Conn]) -> String {
    let uniq_ips: std::collections::BTreeSet<&str> =
        conns.iter().map(|c| c.remote.as_str()).collect();
    let uniq_dom: std::collections::BTreeSet<&str> =
        conns.iter().filter_map(|c| c.domain.as_deref()).collect();
    let tx: u64 = conns.iter().map(|c| c.tx_bytes).sum();
    let rx: u64 = conns.iter().map(|c| c.rx_bytes).sum();

    let rows: String = conns
        .iter()
        .map(|c| {
            format!(
                "<tr><td class=mono>{proto}</td><td>{state}</td><td>{dom}</td>\
                 <td class='mono ip'>{ip}</td><td class=mono>{port}</td>\
                 <td class=dim>{net}</td><td>{proc}</td><td class=mono>{tx}</td>\
                 <td class=mono>{rx}</td></tr>",
                proto = c.proto,
                state = esc(&c.state),
                dom = c.domain.as_deref().map(esc).unwrap_or_else(|| format!(
                    "<span class=dim>{}</span>",
                    tr("no name", "имени нет")
                )),
                ip = esc(&c.remote),
                port = c.rport,
                net = esc(&format!(
                    "{} {}",
                    c.asn.as_deref().unwrap_or(""),
                    c.owner.as_deref().unwrap_or("")
                )),
                proc = c.pname.as_deref().map(esc).unwrap_or_else(|| {
                    format!(
                        "<span class=dim>{}</span>",
                        tr("packets only", "только пакеты")
                    )
                }),
                tx = bytes(c.tx_bytes),
                rx = bytes(c.rx_bytes),
            )
        })
        .collect();

    let domains: String = uniq_dom.iter().map(|d| format!("{}\n", esc(d))).collect();

    format!(
        r#"<!doctype html><html lang={lang}><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>{title}</title><style>
:root{{--bg:#0f1115;--panel:#161a21;--panel2:#1c2129;--line:#2a313c;--txt:#e6e9ef;--dim:#9aa4b2;--accent:#7aa2f7}}
@media (prefers-color-scheme:light){{:root{{--bg:#f6f7f9;--panel:#fff;--panel2:#eef1f5;--line:#d8dee8;
 --txt:#1a1d23;--dim:#5b6472;--accent:#2f5fd0}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--txt);
 font:15px/1.6 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}}
.wrap{{max-width:1180px;margin:0 auto;padding:32px 16px 70px}}
h1{{font-size:26px;margin:0 0 4px;letter-spacing:-.02em}}
.sub{{color:var(--dim);font-size:14px;margin:0 0 24px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}}
.card .n{{font-size:22px;font-weight:600}}.card .l{{font-size:12.5px;color:var(--dim)}}
h2{{font-size:19px;margin:38px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:10px;overflow:hidden;font-size:13.5px}}
th{{background:var(--panel2);text-align:left;padding:9px 11px;font-size:11.5px;color:var(--dim);
 text-transform:uppercase;letter-spacing:.05em}}
td{{padding:8px 11px;border-top:1px solid var(--line)}}
.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}}
.ip{{color:var(--accent);font-weight:600}}.dim{{color:var(--dim)}}
pre{{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:12px 14px;
 font-family:ui-monospace,monospace;font-size:12.5px;overflow-x:auto}}
</style></head><body><div class=wrap>
<h1>{title}</h1><p class=sub>{snap} {generated}</p>
<div class=cards>
<div class=card><div class=n>{nconn}</div><div class=l>{l_conn}</div></div>
<div class=card><div class=n>{nip}</div><div class=l>{l_ip}</div></div>
<div class=card><div class=n>{ndom}</div><div class=l>{l_dom}</div></div>
<div class=card><div class=n>{tx}</div><div class=l>{l_tx}</div></div>
<div class=card><div class=n>{rx}</div><div class=l>{l_rx}</div></div>
</div>
<h2>{h_conns}</h2>
<table><thead><tr><th>Proto<th>{c_state}<th>{c_dom}<th>{c_addr}<th>{c_port}<th>{c_net}<th>{c_proc}<th>{c_out}<th>{c_in}</tr></thead>
<tbody>{rows}</tbody></table>
<h2>{h_doms}</h2><pre>{domains}</pre>
</div></body></html>"#,
        lang = crate::i18n::code(),
        snap = tr("SocketTrail, snapshot of", "SocketTrail, снимок от"),
        l_conn = tr("connections", "соединений"),
        l_ip = tr("unique addresses", "уникальных адресов"),
        l_dom = tr("domains identified", "доменов опознано"),
        l_tx = tr("outgoing traffic", "исходящий трафик"),
        l_rx = tr("incoming traffic", "входящий трафик"),
        h_conns = tr("Connections", "Соединения"),
        c_state = tr("State", "Состояние"),
        c_dom = tr("Domain", "Домен"),
        c_addr = tr("Address", "Адрес"),
        c_port = tr("Port", "Порт"),
        c_net = tr("Network", "Сеть"),
        c_proc = tr("Process", "Процесс"),
        c_out = tr("Out", "Исх."),
        c_in = tr("In", "Вх."),
        h_doms = tr("Domain list", "Список доменов"),
        nconn = conns.len(),
        nip = uniq_ips.len(),
        ndom = uniq_dom.len(),
        tx = bytes(tx),
        rx = bytes(rx),
    )
}
