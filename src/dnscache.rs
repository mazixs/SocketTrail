//! Windows: имена из DNS-кеша системы, без прав администратора и без захвата.
//!
//! DnsGetCacheDataTable (dnsapi.dll, не документирована, ее же использует
//! ipconfig /displaydns) дает список имен в кеше. Адреса к ним берутся тем же
//! DnsQuery_W с DNS_QUERY_NO_WIRE_QUERY: ответ только из кеша, в сеть запрос не уходит.
//! Chrome и Edge разрешают имена своим клиентом, их запросов в кеше нет.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use windows_sys::Win32::NetworkManagement::Dns::{
    DNS_RECORDW, DNS_TYPE_A, DNS_TYPE_AAAA, DnsFree, DnsFreeFlat, DnsFreeRecordList, DnsQuery_W,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

const DNS_QUERY_NO_WIRE_QUERY: u32 = 0x10;

#[repr(C)]
struct CacheEntry {
    next: *mut CacheEntry,
    name: *mut u16,
    ty: u16,
    data_len: u16,
    flags: u32,
}

type GetTable = unsafe extern "system" fn(*mut *mut CacheEntry) -> i32;

fn get_table() -> Option<GetTable> {
    static F: OnceLock<Option<GetTable>> = OnceLock::new();
    *F.get_or_init(|| unsafe {
        let dll: Vec<u16> = "dnsapi.dll".encode_utf16().chain(Some(0)).collect();
        let h = LoadLibraryW(dll.as_ptr());
        if h.is_null() {
            return None;
        }
        GetProcAddress(h, c"DnsGetCacheDataTable".as_ptr().cast())
            .map(|f| std::mem::transmute::<_, GetTable>(f))
    })
}

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

/// Имена A/AAAA из кеша.
fn cached_names() -> Vec<(String, u16)> {
    let mut out = Vec::new();
    let Some(f) = get_table() else { return out };
    let mut head: *mut CacheEntry = std::ptr::null_mut();
    if unsafe { f(&mut head) } == 0 {
        return out;
    }
    let mut e = head;
    while !e.is_null() {
        let cur = unsafe { &*e };
        if cur.ty == DNS_TYPE_A || cur.ty == DNS_TYPE_AAAA {
            let name = unsafe { wstr(cur.name) };
            if !name.is_empty() {
                out.push((name.to_ascii_lowercase(), cur.ty));
            }
        }
        let next = cur.next;
        unsafe {
            if !cur.name.is_null() {
                DnsFree(cur.name.cast(), DnsFreeFlat);
            }
            DnsFree(e.cast(), DnsFreeFlat);
        }
        e = next;
    }
    out
}

fn cached_addrs(name: &str, ty: u16, out: &mut Vec<(String, IpAddr)>) {
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut res: *mut DNS_RECORDW = std::ptr::null_mut();
    let rc = unsafe {
        DnsQuery_W(
            wide.as_ptr(),
            ty,
            DNS_QUERY_NO_WIRE_QUERY,
            std::ptr::null_mut(),
            (&mut res as *mut *mut DNS_RECORDW).cast(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        return;
    }
    let mut r = res;
    while !r.is_null() {
        let rec = unsafe { &*r };
        let ip = unsafe {
            match rec.wType {
                DNS_TYPE_A => Some(IpAddr::V4(Ipv4Addr::from(
                    rec.Data.A.IpAddress.to_ne_bytes(),
                ))),
                DNS_TYPE_AAAA => Some(IpAddr::V6(Ipv6Addr::from(rec.Data.AAAA.Ip6Address.IP6Byte))),
                _ => None,
            }
        };
        // Имя - то, что спрашивала программа, а не конец цепочки CNAME: так же, как в пакетном разборе.
        if let Some(ip) = ip
            && !ip.is_unspecified()
        {
            out.push((name.to_string(), ip));
        }
        r = rec.pNext;
    }
    if !res.is_null() {
        unsafe { DnsFree(res.cast(), DnsFreeRecordList) };
    }
}

/// Пары (имя, адрес) из кеша. Блокирующий вызов, сотни записей - десятки миллисекунд.
pub fn snapshot() -> Vec<(String, IpAddr)> {
    let mut out = Vec::new();
    for (name, ty) in cached_names() {
        cached_addrs(&name, ty, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Под Wine функция есть, но кеш пустой: проверяем только, что вызов не падает.
    #[test]
    fn snapshot_does_not_crash() {
        let _ = std::net::ToSocketAddrs::to_socket_addrs(&("localhost", 80));
        let s = snapshot();
        assert!(s.iter().all(|(n, _)| !n.is_empty()));
    }
}
