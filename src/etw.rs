//! Windows: захват пакетов без Npcap и Wireshark.
//!
//! Драйвер PktMon встроен в Windows 10 2004+ и 11. Включает его штатная утилита
//! pktmon, а пакеты мы читаем сами - из своей ETW-сессии реального времени на
//! провайдере Microsoft-Windows-PktMon (событие 160, кадр целиком). Нужны права
//! администратора: и pktmon, и ETW-сессии без них недоступны.

use std::collections::{HashSet, VecDeque};
use std::io::{BufWriter, Write};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};

use crate::capture::PacketSender;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Globalization::{CP_OEMCP, MultiByteToWideChar};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace, QueryAllTracesW, StartTraceW, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

use crate::i18n::Text;
use crate::pcap;

const SESSION_PREFIX: &str = "SocketTrail-";

fn session_name() -> String {
    format!("{SESSION_PREFIX}{}", std::process::id())
}
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Предел памяти под кадры в очереди к рабочему потоку: запись на медленный диск не
/// должна ни терять всплеск трафика, ни съедать всю память при долгом отставании.
const QUEUE_BYTES: usize = 256 << 20;
const EVENT_PACKET: u16 = 160;
/// Поля события 160 до Payload: PktGroupId u64, 7 x u16, 2 x u32, 2 x u16.
const HEADER: usize = 34;

/// Microsoft-Windows-PktMon {4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac}
const PKTMON: windows_sys::core::GUID =
    windows_sys::core::GUID::from_u128(0x4d4f80d9_c8bd_4d73_bb5b_19c90402c5ac);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn pktmon_exe() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join("PktMon.exe")
}

fn etl_path() -> PathBuf {
    crate::paths::cache_dir().join("pktmon.etl")
}

fn pktmon(args: &[&str]) -> Result<String, String> {
    let out = Command::new(pktmon_exe())
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| t!("pktmon did not start: {e}", "pktmon не запустился: {e}"))?;
    let mut text = console_text(&out.stdout).trim().to_string();
    if text.is_empty() {
        text = console_text(&out.stderr).trim().to_string();
    }
    if out.status.success() {
        Ok(text)
    } else {
        Err(format!("pktmon {}: {text}", args.join(" ")))
    }
}

/// Консольные утилиты пишут в кодировке OEM (866 на русской системе), а не в UTF-8.
fn console_text(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    let Ok(len) = i32::try_from(bytes.len()) else {
        return String::from_utf8_lossy(bytes).into_owned();
    };
    // SAFETY: длины переданы вместе с буферами, размер результата запрошен первым вызовом.
    unsafe {
        let need = MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), len, std::ptr::null_mut(), 0);
        if need <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; need as usize];
        let got = MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), need);
        String::from_utf16_lossy(&wide[..got.max(0) as usize])
    }
}

pub fn probe() -> Result<(), Text> {
    if !pktmon_exe().is_file() {
        return Err(text!(
            "PktMon is missing (Windows 10 version 2004 or newer is required).",
            "В системе нет PktMon (нужна Windows 10 версии 2004 или новее)."
        ));
    }
    if !crate::elevate::is_elevated() {
        return Err(need_admin());
    }
    Ok(())
}

/// Имеет ли смысл предлагать перезапуск от администратора.
pub fn can_elevate() -> bool {
    pktmon_exe().is_file() && !crate::elevate::is_elevated()
}

pub fn need_admin() -> Text {
    text!(
        "Domains come from the Windows DNS cache, Chrome and Edge will have none. \
         For browser domains, traffic volume and dumps, restart SocketTrail as administrator.",
        "Домены берутся из DNS-кеша Windows, у Chrome и Edge их не будет. \
         Для доменов браузеров, объема трафика и дампов перезапустите SocketTrail от имени администратора."
    )
}

struct Dedup {
    order: VecDeque<(u64, u16)>,
    set: HashSet<(u64, u16)>,
}

impl Dedup {
    /// Один пакет проходит несколько компонентов стека с одним PktGroupId.
    fn first(&mut self, id: (u64, u16)) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > 8192
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        true
    }
}

struct DumpWriter {
    out: BufWriter<std::fs::File>,
    error: Option<String>,
}

enum Work {
    Frame(Vec<u8>, i64),
    Start(String, mpsc::Sender<std::io::Result<()>>),
    Stop(mpsc::Sender<std::io::Result<()>>),
    Shutdown,
}
struct Sink {
    queue: mpsc::Sender<Work>,
    /// Объем кадров, ожидающих рабочий поток.
    queued: AtomicUsize,
    metrics: std::sync::Arc<crate::capture::Metrics>,
    error: Mutex<Option<String>>,
    bad: AtomicU64,
}

impl Sink {
    fn new(queue: mpsc::Sender<Work>, metrics: std::sync::Arc<crate::capture::Metrics>) -> Self {
        Self {
            queue,
            queued: AtomicUsize::new(0),
            metrics,
            error: Mutex::new(None),
            bad: AtomicU64::new(0),
        }
    }

    /// Вызывается из callback ETW: он не должен ждать ни диск, ни разбор, иначе потери
    /// происходят уже в буферах самой сессии. Очередь ограничена объемом, а не числом
    /// кадров: на ровном потоке она пуста, а всплеск спокойно переживает.
    fn push(&self, data: &[u8], stamp: i64) {
        let len = data.len();
        if self.queued.fetch_add(len, Ordering::Relaxed) + len > QUEUE_BYTES {
            self.queued.fetch_sub(len, Ordering::Relaxed);
            self.metrics.lost_frames.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.queue.send(Work::Frame(data.to_vec(), stamp)).is_err() {
            self.queued.fetch_sub(len, Ordering::Relaxed);
        }
    }
}

// Только ограниченная копия события в callback. Разбор и диск - в рабочем потоке.
fn consume(events: mpsc::Receiver<Work>, tx: PacketSender, sink: &Sink) {
    let mut seen = Dedup {
        order: VecDeque::new(),
        set: HashSet::new(),
    };
    let mut parsers = pcap::Parsers::default();
    let mut dump: Option<DumpWriter> = None;
    while let Ok(event) = events.recv() {
        match event {
            Work::Frame(data, stamp) => {
                sink.queued.fetch_sub(data.len(), Ordering::Relaxed);
                match packet(&data) {
                    Some((group, number, linktype, orig, frame)) => {
                        if linktype == 0 {
                            sink.metrics.unsupported.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        if !seen.first((group, number)) {
                            continue;
                        }
                        if let Some(w) = dump.as_mut() {
                            let iface = if linktype == 1 { 0 } else { 1 };
                            if w.error.is_none()
                                && let Err(e) = write_epb(&mut w.out, iface, stamp, frame, orig)
                            {
                                w.error = Some(e.to_string());
                                *sink.error.lock().unwrap() = w.error.clone();
                            }
                        }
                        if let Some(packet) = pcap::parse_link_live(linktype, frame, &mut parsers) {
                            let _ = tx.send(packet);
                        }
                    }
                    None => {
                        sink.bad.fetch_add(1, Ordering::Relaxed);
                        sink.metrics.unsupported.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Work::Start(path, reply) => {
                let result = if dump.is_some() {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        t!("Recording is already running", "Запись уже идет"),
                    ))
                } else {
                    (|| {
                        let file = crate::paths::new_private_file(path.as_ref())?;
                        let mut out = BufWriter::with_capacity(1 << 20, file);
                        write_header(&mut out)?;
                        out.flush()?;
                        dump = Some(DumpWriter { out, error: None });
                        *sink.error.lock().unwrap() = None;
                        Ok(())
                    })()
                };
                let _ = reply.send(result);
            }
            Work::Stop(reply) => {
                let result = if let Some(mut writer) = dump.take() {
                    let flush = writer.out.flush();
                    writer
                        .error
                        .map_or(flush, |e| Err(std::io::Error::other(e)))
                } else {
                    Ok(())
                };
                let _ = reply.send(result);
            }
            Work::Shutdown => break,
        }
    }
}

static SINK: OnceLock<Sink> = OnceLock::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Работающий захват. Drop останавливает сессию и pktmon.
pub struct Session {
    control: CONTROLTRACE_HANDLE,
    thread: Option<std::thread::JoinHandle<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

#[repr(C)]
struct Props {
    p: EVENT_TRACE_PROPERTIES,
    name: [u16; 64],
}

fn props() -> Box<Props> {
    let mut b: Box<Props> = Box::new(unsafe { std::mem::zeroed() });
    b.p.Wnode.BufferSize = std::mem::size_of::<Props>() as u32;
    b.p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    b.p.Wnode.ClientContext = 2; // системное время, ProcessTrace отдает FILETIME
    b.p.BufferSize = 256;
    b.p.MinimumBuffers = 16;
    b.p.MaximumBuffers = 256;
    b.p.FlushTimer = 1;
    b.p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    b.p.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    b
}

fn stop_session(name: &str) {
    let name = wide(name);
    let mut p = props();
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name.as_ptr(),
            &mut p.p,
            EVENT_TRACE_CONTROL_STOP,
        )
    };
}

/// Сколько событий потеряла наша сессия: при записи это кадры, которых нет в файле.
pub fn events_lost() -> u64 {
    if !is_active() {
        return 0;
    }
    let name = wide(&session_name());
    let mut p = props();
    let rc = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name.as_ptr(),
            &mut p.p,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    if rc != 0 {
        return 0;
    }
    u64::from(p.p.EventsLost) + u64::from(p.p.RealTimeBuffersLost)
}

/// PID из имени нашей сессии, если процесс с таким номером уже завершен.
fn stale_session_pid(name: &str, alive: impl Fn(u32) -> bool) -> Option<u32> {
    let pid = name.strip_prefix(SESSION_PREFIX)?.parse().ok()?;
    (pid != std::process::id() && !alive(pid)).then_some(pid)
}

fn process_alive(pid: u32) -> bool {
    // SAFETY: дескриптор проверяется и сразу закрывается.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            // Защищенный процесс не открывается, но он жив, это не наш завершившийся.
            return std::io::Error::last_os_error().raw_os_error() == Some(5);
        }
        CloseHandle(h);
    }
    true
}

/// После аварийного завершения ETW-сессия остается в системе и продолжает занимать
/// память ядра. Их число ограничено, поэтому при старте убираем свои брошенные.
fn stop_stale_sessions() {
    #[repr(C)]
    struct Query {
        p: EVENT_TRACE_PROPERTIES,
        logger: [u16; 256],
        file: [u16; 256],
    }
    const MAX: usize = 64;
    let mut list: Vec<Box<Query>> = (0..MAX)
        .map(|_| {
            let mut q: Box<Query> = Box::new(unsafe { std::mem::zeroed() });
            q.p.Wnode.BufferSize = std::mem::size_of::<Query>() as u32;
            q.p.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            q.p.LogFileNameOffset = q.p.LoggerNameOffset + std::mem::size_of::<[u16; 256]>() as u32;
            q
        })
        .collect();
    let mut pointers: Vec<*mut EVENT_TRACE_PROPERTIES> =
        list.iter_mut().map(|q| &mut q.p as *mut _).collect();
    let mut count = 0u32;
    // SAFETY: каждый элемент массива указывает на буфер указанного в BufferSize размера.
    let rc = unsafe { QueryAllTracesW(pointers.as_mut_ptr(), MAX as u32, &mut count) };
    if rc != 0 {
        return;
    }
    for q in list.iter().take(count as usize) {
        let end = q
            .logger
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(q.logger.len());
        let name = String::from_utf16_lossy(&q.logger[..end]);
        if stale_session_pid(&name, process_alive).is_some() {
            stop_session(&name);
        }
    }
}

/// Запуск PktMon. Захват общесистемный, и чужую сессию останавливать нельзя. Если же в
/// status указан наш файл, это прошлый запуск SocketTrail, завершившийся аварийно:
/// без остановки он навсегда оставил бы захват недоступным.
fn start_pktmon(etl: &str) -> Result<(), String> {
    let args = [
        "start",
        "--capture",
        "--comp",
        "nics",
        "--pkt-size",
        "0",
        "--file-name",
        etl,
        "--file-size",
        "16",
        "--log-mode",
        "memory",
    ];
    let Err(first) = pktmon(&args) else {
        return Ok(());
    };
    let status = pktmon(&["status"]).unwrap_or_else(|text| text);
    if !status.to_lowercase().contains(&etl.to_lowercase()) {
        return Err(first);
    }
    let _ = pktmon(&["stop"]);
    pktmon(&args).map(|_| ())
}

pub fn start(tx: PacketSender) -> Result<Session, Text> {
    probe()?;
    let (queue, events) = mpsc::channel();
    if SINK.set(Sink::new(queue, tx.metrics.clone())).is_err() {
        return Err(t!("capture is already running", "захват уже запущен").into());
    }
    stop_stale_sessions();

    let etl = etl_path();
    let _ = std::fs::create_dir_all(etl.parent().unwrap_or(&etl));
    let etl_s = etl.display().to_string();
    // nics - только сетевые адаптеры, без промежуточных компонентов стека;
    // memory - буфер в памяти, диск во время работы не трогается.
    start_pktmon(&etl_s)?;

    let name = wide(&session_name());
    let mut p = props();
    let mut control = CONTROLTRACE_HANDLE { Value: 0 };
    let rc = unsafe { StartTraceW(&mut control, name.as_ptr(), &mut p.p) };
    if rc != 0 {
        let _ = pktmon(&["stop"]);
        return Err(t!(
            "ETW session not created, code {rc}",
            "ETW-сессия не создана, код {rc}"
        )
        .into());
    }
    let rc = unsafe {
        EnableTraceEx2(
            control,
            &PKTMON,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION as u8,
            0,
            0,
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        stop_session(&session_name());
        let _ = pktmon(&["stop"]);
        return Err(t!(
            "PktMon provider not enabled, code {rc}",
            "провайдер PktMon не включен, код {rc}"
        )
        .into());
    }

    let worker = std::thread::spawn(move || consume(events, tx, SINK.get().unwrap()));
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        let mut name = wide(&session_name());
        let mut log: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        log.LoggerName = name.as_mut_ptr();
        log.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log.Anonymous2.EventRecordCallback = Some(on_event);
        let h = unsafe { OpenTraceW(&mut log) };
        if h.Value == u64::MAX {
            let error = std::io::Error::last_os_error();
            let _ = ready_tx.send(Err(error));
            return;
        }
        ACTIVE.store(true, Ordering::Release);
        let _ = ready_tx.send(Ok(()));
        unsafe {
            ProcessTrace(
                &h as *const PROCESSTRACE_HANDLE,
                1,
                std::ptr::null(),
                std::ptr::null(),
            );
            CloseTrace(h);
        }
        ACTIVE.store(false, Ordering::Release);
    });
    let session = Session {
        control,
        thread: Some(thread),
        worker: Some(worker),
    };
    match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(Ok(())) => Ok(session),
        result => {
            let error = match result {
                Ok(Err(e)) => e.to_string(),
                Err(e) => e.to_string(),
                Ok(Ok(())) => unreachable!(),
            };
            drop(session);
            Err(text!(
                "ETW reader did not start: {error}",
                "Чтение ETW не запустилось: {error}"
            ))
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Release);
        if let Err(e) = dump_stop() {
            eprintln!("[dump] {e}");
        }
        let mut p = props();
        unsafe {
            ControlTraceW(
                self.control,
                std::ptr::null(),
                &mut p.p,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if let Some(sink) = SINK.get() {
            let _ = sink.queue.send(Work::Shutdown);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = pktmon(&["stop"]);
        let _ = std::fs::remove_file(etl_path());
        if let Some(s) = SINK.get() {
            let bad = s.bad.load(Ordering::Relaxed);
            if bad > 0 {
                eprintln!("[capture] events in unknown format: {bad}");
            }
        }
    }
}

fn same_guid(a: &windows_sys::core::GUID, b: &windows_sys::core::GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

unsafe extern "system" fn on_event(ev: *mut EVENT_RECORD) {
    let ev = unsafe { &*ev };
    let h = &ev.EventHeader;
    if h.EventDescriptor.Id != EVENT_PACKET || !same_guid(&h.ProviderId, &PKTMON) {
        return;
    }
    let Some(sink) = SINK.get() else { return };
    if ev.UserData.is_null() {
        return;
    }
    let data =
        unsafe { std::slice::from_raw_parts(ev.UserData as *const u8, ev.UserDataLength as usize) };
    sink.push(data, h.TimeStamp);
}

/// (PktGroupId, PktNumber, linktype pcap, исходная длина, кадр). Раскладку сверяем по длине:
/// если в новой версии Windows поля поменяются, событие просто не разберется.
fn packet(d: &[u8]) -> Option<(u64, u16, u16, u32, &[u8])> {
    let u16at = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]);
    if d.len() < HEADER {
        return None;
    }
    let group = u64::from_le_bytes(d[0..8].try_into().ok()?);
    let number = u16at(8);
    let ptype = u16at(14);
    let orig = u16at(30) as u32;
    let logged = u16at(32) as usize;
    if HEADER + logged != d.len() {
        return None;
    }
    let linktype = match ptype {
        1 => 1,   // Ethernet
        3 => 101, // IP без канального заголовка
        _ => return Some((group, number, 0, orig, &d[HEADER..])),
    };
    Some((
        group,
        number,
        linktype,
        orig.max(logged as u32),
        &d[HEADER..],
    ))
}

fn block(out: &mut impl Write, ty: u32, body: &[u8]) -> std::io::Result<()> {
    let pad = (4 - body.len() % 4) % 4;
    let len = (12 + body.len() + pad) as u32;
    out.write_all(&ty.to_le_bytes())?;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(body)?;
    out.write_all(&[0u8; 3][..pad])?;
    out.write_all(&len.to_le_bytes())
}

fn write_header(out: &mut impl Write) -> std::io::Result<()> {
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    block(out, 0x0A0D_0D0A, &shb)?;
    for linktype in [1u16, 101] {
        let mut idb = Vec::new();
        idb.extend_from_slice(&linktype.to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&0u32.to_le_bytes());
        block(out, 1, &idb)?;
    }
    Ok(())
}

/// FILETIME (100 нс с 1601 года) -> микросекунды с 1970 года, как ждет pcapng по умолчанию.
fn write_epb(
    out: &mut impl Write,
    iface: u32,
    filetime: i64,
    frame: &[u8],
    orig: u32,
) -> std::io::Result<()> {
    let us = (filetime / 10 - 11_644_473_600_000_000).max(0) as u64;
    let mut b = Vec::with_capacity(20 + frame.len());
    b.extend_from_slice(&iface.to_le_bytes());
    b.extend_from_slice(&((us >> 32) as u32).to_le_bytes());
    b.extend_from_slice(&(us as u32).to_le_bytes());
    b.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    b.extend_from_slice(&orig.max(frame.len() as u32).to_le_bytes());
    b.extend_from_slice(frame);
    block(out, 6, &b)
}

/// Запись дампа из уже идущего захвата.
pub fn dump_start(path: &str) -> std::io::Result<()> {
    if !is_active() {
        return Err(std::io::Error::other(t!(
            "capture is not running",
            "захват не запущен"
        )));
    }
    let sink = SINK
        .get()
        .ok_or_else(|| std::io::Error::other(t!("capture is not running", "захват не запущен")))?;
    let (reply, result) = mpsc::channel();
    sink.queue
        .send(Work::Start(path.to_string(), reply))
        .map_err(|_| {
            std::io::Error::other(t!("ETW worker stopped", "Рабочий поток ETW остановился"))
        })?;
    result.recv().map_err(|_| {
        std::io::Error::other(t!("ETW worker stopped", "Рабочий поток ETW остановился"))
    })?
}

pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

pub fn dump_error() -> Option<String> {
    if !is_active() {
        return Some(t!("Packet capture stopped", "Пакетный захват остановился"));
    }
    SINK.get().and_then(|s| s.error.lock().unwrap().clone())
}

pub fn dump_stop() -> std::io::Result<()> {
    let Some(sink) = SINK.get() else {
        return Ok(());
    };
    let (reply, result) = mpsc::channel();
    sink.queue.send(Work::Stop(reply)).map_err(|_| {
        std::io::Error::other(t!("ETW worker stopped", "Рабочий поток ETW остановился"))
    })?;
    result.recv().map_err(|_| {
        std::io::Error::other(t!("ETW worker stopped", "Рабочий поток ETW остановился"))
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(ptype: u16, frame: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&42u64.to_le_bytes());
        for v in [1u16, 1, 1, ptype, 7, 0, 0] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.extend_from_slice(&[0u8; 8]);
        d.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        d.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        d.extend_from_slice(frame);
        d
    }

    #[test]
    fn parses_packet_event() {
        let frame = [0xAAu8; 60];
        let d = event(1, &frame);
        let (g, number, lt, orig, f) = packet(&d).unwrap();
        assert_eq!(number, 1);
        assert_eq!((g, lt, orig, f.len()), (42, 1, 60, 60));
        let mut bad = d.clone();
        bad.pop();
        assert!(packet(&bad).is_none());
    }

    #[test]
    fn writes_readable_pcapng() {
        // UDP-пакет в Ethernet: наш же разборщик должен прочитать записанное.
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        let ip = [
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 1, 1, 1, 1,
        ];
        f.extend_from_slice(&ip);
        f.extend_from_slice(&[0x30, 0x39, 0, 53, 0, 8, 0, 0]);
        let mut out = Vec::new();
        write_header(&mut out).unwrap();
        write_epb(&mut out, 0, 133_000_000_000_000_000, &f, f.len() as u32).unwrap();
        let mut r = pcap::PcapngReader::new();
        let mut pk = Vec::new();
        r.push(&out, &mut pk);
        assert_eq!(pk.len(), 1);
        assert_eq!(pk[0].dport, 53);
    }
    #[test]
    fn packet_group_keeps_distinct_numbers_and_drops_component_duplicates() {
        let mut d = Dedup {
            order: VecDeque::new(),
            set: HashSet::new(),
        };
        assert!(d.first((42, 1)));
        assert!(d.first((42, 2)));
        assert!(!d.first((42, 1)));
        for id in 0..9000 {
            d.first((id + 100, 1));
        }
        assert_eq!(d.set.len(), 8192);
        assert_eq!(d.order.len(), 8192);
    }

    #[test]
    fn worker_orders_recording_controls_and_drains_queued_frames() {
        let dir = crate::paths::TestDir::new("etw-worker");
        let path = dir.0.join("demo.pcapng");
        let (queue, events) = mpsc::channel();
        let metrics = std::sync::Arc::new(crate::capture::Metrics::default());
        let sink = Sink::new(queue, metrics.clone());
        let (packets, mut received) = tokio::sync::mpsc::channel(4);
        std::thread::scope(|scope| {
            let worker =
                scope.spawn(|| consume(events, PacketSender::new(packets, metrics), &sink));
            let (reply, result) = mpsc::channel();
            sink.queue
                .send(Work::Start(path.to_string_lossy().into_owned(), reply))
                .unwrap();
            result.recv().unwrap().unwrap();
            let frame = [
                0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1, 0x9c,
                0x40, 0x01, 0xbb, 0, 8, 0, 0,
            ];
            let first = event(3, &frame);
            let mut next = first.clone();
            next[8..10].copy_from_slice(&2u16.to_le_bytes());
            for data in [first.clone(), first, next] {
                sink.push(&data, 133_000_000_000_000_000);
            }
            let (reply, result) = mpsc::channel();
            sink.queue.send(Work::Stop(reply)).unwrap();
            result.recv().unwrap().unwrap();
            sink.queue.send(Work::Shutdown).unwrap();
            worker.join().unwrap();
        });
        assert_eq!(sink.queued.load(Ordering::Relaxed), 0);
        assert_eq!(received.len(), 2);
        assert_eq!(received.try_recv().unwrap().sport, 40000);
        let mut reader = pcap::PcapngReader::new();
        let mut frames = Vec::new();
        reader.push(&std::fs::read(path).unwrap(), &mut frames);
        assert_eq!(frames.len(), 2);
    }

    #[test]
    fn unknown_packet_types_are_not_counted_as_lost_traffic() {
        let (queue, events) = mpsc::channel();
        let metrics = std::sync::Arc::new(crate::capture::Metrics::default());
        let sink = Sink::new(queue, metrics.clone());
        let (packets, _received) = tokio::sync::mpsc::channel(4);
        sink.push(&event(7, &[0xAA; 60]), 133_000_000_000_000_000);
        sink.push(&[1, 2, 3], 133_000_000_000_000_000);
        sink.queue.send(Work::Shutdown).unwrap();
        consume(events, PacketSender::new(packets, metrics.clone()), &sink);
        assert_eq!(metrics.unsupported.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.dropped.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.lost_frames.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn frames_over_the_memory_budget_are_counted_as_lost() {
        let (queue, events) = mpsc::channel();
        let metrics = std::sync::Arc::new(crate::capture::Metrics::default());
        let sink = Sink::new(queue, metrics.clone());
        sink.queued.store(QUEUE_BYTES - 10, Ordering::Relaxed);
        sink.push(&[0u8; 10], 1);
        sink.push(&[0u8; 1], 2);
        assert_eq!(metrics.lost_frames.load(Ordering::Relaxed), 1);
        assert_eq!(sink.queued.load(Ordering::Relaxed), QUEUE_BYTES);
        assert_eq!(events.try_iter().count(), 1);
    }

    #[test]
    fn only_our_sessions_of_finished_processes_are_stale() {
        let dead = |_: u32| false;
        assert_eq!(stale_session_pid("SocketTrail-4242", dead), Some(4242));
        assert_eq!(stale_session_pid("SocketTrail-4242", |_| true), None);
        assert_eq!(
            stale_session_pid(&format!("SocketTrail-{}", std::process::id()), dead),
            None
        );
        assert_eq!(stale_session_pid("EventLog-System", dead), None);
        assert_eq!(stale_session_pid("SocketTrail-backup", dead), None);
    }

    #[test]
    fn console_output_in_utf8_is_kept_and_other_bytes_do_not_panic() {
        assert_eq!(console_text(b"ok"), "ok");
        assert_eq!(console_text("ошибка".as_bytes()), "ошибка");
        assert!(!console_text(&[0xAE, 0xE8, 0xA8, 0xA1, 0xAA, 0xA0]).is_empty());
    }
}
