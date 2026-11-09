//! Жизненный цикл записи дампа: старт, сбор сведений о соединениях, остановка и
//! обработка файла.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::annotate::{self, Owner};
use crate::app::{App, Shared, lock};
use crate::capture::{self, Losses};
use crate::dumpfile::{self, ConnRecord, Options, Recording};
use crate::localtime::{human_time, stamp};
use crate::paths;
use crate::procs::{self, ProcInfo};
use crate::state::{self, Conn, ConnKey};

/// Через столько после выхода всех процессов группы запись "только процесс" останавливается сама.
const DUMP_IDLE_MS: u64 = 15_000;
/// Предел карты соединений. Запись он не останавливает: файл пишется и дальше.
const MAX_DUMP_CONNS: usize = 100_000;
pub const MAX_DUMP_PROCS: usize = 4096;

/// Процесс и подтвержденные соединения сохраняются до завершения дампа.
pub struct DumpMeta {
    pub process: Option<ProcInfo>,
    pub only_group: bool,
    options: Options,
    /// все процессы группы, замеченные за время записи
    pub pids: HashSet<i32>,
    pub instances: HashSet<procs::Identity>,
    limit_reached: bool,
    losses_at_start: Losses,
    pub started: u64,
    pub last_alive: u64,
    /// Строки таблицы, не менявшиеся с этого момента, сверять незачем.
    synced_at: u64,
    /// Подтвержденные соединения записи не теряются при очистке/вытеснении
    /// общей истории. Спорное владение одним кортежем остается без подписи.
    pub conns: HashMap<ConnKey, Conn>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum DumpPhase {
    #[default]
    Idle,
    Starting,
    Recording,
    Finishing,
}

#[derive(Clone, Default, Serialize)]
pub struct DumpOutcome {
    pub ok: bool,
    pub path: Option<String>,
    pub size: u64,
    pub sidecar: Option<String>,
    pub error: Option<String>,
    pub warnings: Vec<String>,
    pub unfiltered: bool,
    pub parts: usize,
}

impl DumpOutcome {
    pub fn failed(error: String) -> Self {
        Self {
            error: Some(error),
            ..Self::default()
        }
    }
}

/// Имя exe бывает до 255 байт, с суффиксом это ENAMETOOLONG. Предел файловой
/// системы считается в байтах, поэтому и обрезка по байтам.
fn dump_file_stem(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        let c = if c.is_alphanumeric() || c == '.' || c == '-' {
            c
        } else {
            '_'
        };
        if out.len() + c.len_utf8() > 64 {
            break;
        }
        out.push(c);
    }
    out
}

/// Незанятое имя файла: две записи за одну секунду не должны попасть в один файл.
fn free_dump_path(dir: &Path, stem: &str, when: &str) -> PathBuf {
    let path = dir.join(format!("{stem}-{when}.pcapng"));
    if !path.exists() {
        return path;
    }
    (2u32..)
        .map(|n| dir.join(format!("{stem}-{when}-{n}.pcapng")))
        .find(|p| !p.exists())
        .unwrap_or(path)
}

pub async fn start_dump(app: Shared, filtered: bool, options: Options) -> Value {
    let (mut dump, iface, name, process, pids, instances, losses_at_start) = {
        let mut g = lock(&app);
        if g.dump_phase != DumpPhase::Idle {
            return json!({"ok": false, "error": t!(
                "A recording is already running or being finalized",
                "Запись уже идет или еще завершается"
            )});
        }
        if !g.capture_on {
            return json!({"ok": false, "error": t!(
                "Packet capture is unavailable", "Пакетный захват недоступен"
            )});
        }
        let process = g.selected.and_then(|pid| {
            g.procs
                .iter()
                .find(|p| p.pid == pid && Some(p.identity()) == g.selected_instance)
                .cloned()
        });
        if filtered && process.as_ref().is_none_or(|p| p.started == 0) {
            return json!({"ok": false, "error": t!(
                "Select a running process before recording its traffic",
                "Перед записью трафика выберите работающий процесс"
            )});
        }
        if g.group.len() > MAX_DUMP_PROCS {
            return json!({"ok": false, "error": t!(
                "The process group exceeds the recording metadata limit",
                "Группа процессов превышает лимит метаданных записи"
            )});
        }
        let name = process
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "host".into());
        g.dump_phase = DumpPhase::Starting;
        (
            std::mem::take(&mut g.dump),
            g.iface.clone(),
            name,
            process,
            g.group.iter().copied().collect(),
            g.procs
                .iter()
                .filter(|p| g.group.contains(&p.pid) && p.started != 0)
                .map(ProcInfo::identity)
                .collect(),
            g.capture_metrics.losses(),
        )
    };
    let dir = paths::dumps_dir();
    let path = free_dump_path(&dir, &dump_file_stem(&name), &stamp());
    let path = path.to_string_lossy().into_owned();
    let result = match std::fs::create_dir_all(&dir) {
        Ok(()) => dump.start(&iface, &path).await,
        Err(e) => Err(e),
    };
    let mut g = lock(&app);
    g.dump = dump;
    if let Err(e) = result {
        g.dump_phase = DumpPhase::Idle;
        g.dump_outcome = Some(DumpOutcome::failed(e.to_string()));
        return json!({"ok": false, "error": e.to_string()});
    }
    let t = g.dump.started_ms.unwrap_or_else(state::now_ms);
    g.dump_meta = Some(DumpMeta {
        process,
        only_group: filtered,
        options,
        pids,
        instances,
        limit_reached: false,
        losses_at_start,
        started: t,
        last_alive: t,
        synced_at: t,
        conns: HashMap::new(),
    });
    g.dump_phase = DumpPhase::Recording;
    g.dump_outcome = None;
    g.auto_stopped = None;
    sync(&mut g);
    json!({"ok": true, "path": path, "only": filtered.then_some(name)})
}

/// Завершение держит фазу Finishing до остановки захвата и обработки файла.
async fn wait_packet_accounting(metrics: &capture::Metrics) -> bool {
    let target = metrics.accepted.load(Ordering::Acquire);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while metrics.processed.load(Ordering::Acquire) < target {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

/// Запись завершается сама, если отказал захват или вышли все процессы группы.
pub fn should_stop(g: &mut App) -> bool {
    if g.dump_phase != DumpPhase::Recording {
        return false;
    }
    let failed = g.dump.poll_error().is_some();
    let idle = g.dump_meta.as_ref().is_some_and(|m| {
        m.only_group && state::now_ms().saturating_sub(m.last_alive) > DUMP_IDLE_MS
    });
    failed || idle
}

/// Потери не мешают обработке файла, они только делают его неполным: об этом сообщает
/// предупреждение и признак capture_complete.
fn capture_warnings(m: &DumpMeta, lost: Losses, accounted: bool) -> (Vec<String>, bool) {
    let mut warnings = Vec::new();
    if lost.lost_frames > 0 {
        let n = lost.lost_frames;
        warnings.push(t!(
            "{n} frames did not reach the file: capture could not keep up with the traffic",
            "{n} кадров не попали в файл: захват не успевал за трафиком"
        ));
    }
    if lost.dropped > 0 {
        let n = lost.dropped;
        warnings.push(t!(
            "Packet tracking skipped {n} packets: the file has them, but some connections may have no owner",
            "Пакетный учет пропустил {n} пакетов: в файле они есть, но у части соединений может не быть владельца"
        ));
    }
    if m.limit_reached {
        warnings.push(t!(
            "The connection map reached its limit: connections beyond it have no labels and do not pass the process filter",
            "Карта соединений достигла предела: соединения сверх него остались без подписи и не проходят отбор процесса"
        ));
    }
    if !accounted {
        warnings.push(t!(
            "Packet tracking had not finished when the file was processed",
            "К началу обработки файла пакетный учет не завершился"
        ));
    }
    let complete = lost.lost_frames == 0 && lost.dropped == 0 && !m.limit_reached && accounted;
    (warnings, complete)
}

pub async fn finish_dump(app: &Shared, automatic: bool) -> DumpOutcome {
    let (mut dump, meta, progress) = {
        let mut g = lock(app);
        if g.dump_phase != DumpPhase::Recording {
            return if automatic {
                DumpOutcome::default()
            } else {
                DumpOutcome::failed(t!(
                    "No recording is running, or another operation is in progress",
                    "Запись не идет или другая операция еще выполняется"
                ))
            };
        }
        if automatic && !should_stop(&mut g) {
            return DumpOutcome::default();
        }
        g.dump_phase = DumpPhase::Finishing;
        sync(&mut g);
        let dump = std::mem::take(&mut g.dump);
        g.dump.path = dump.path.clone();
        (dump, g.dump_meta.take(), g.dump_progress.clone())
    };
    let stopped = dump.stop().await;
    let metrics = lock(app).capture_metrics.clone();
    let accounted = wait_packet_accounting(&metrics).await;

    let path = dump.path.clone();
    let mut outcome = DumpOutcome {
        path: path.clone(),
        ..DumpOutcome::default()
    };
    let mut errors = Vec::new();
    if let Err(e) = stopped {
        errors.push(e.to_string());
    }
    if let (Some(p), Some(mut m)) = (&path, meta) {
        let lost = metrics.losses().since(m.losses_at_start);
        let (warnings, complete) = capture_warnings(&m, lost, accounted);
        let options = m.options;
        let only_group = m.only_group;
        let rec = {
            let g = lock(app);
            recording_of(&g, &mut m, warnings, complete, lost)
        };
        let file = PathBuf::from(p);
        let job = progress.clone();
        let processed =
            tokio::task::spawn_blocking(move || dumpfile::process(&file, rec, options, &job)).await;
        match processed {
            Ok(done) => {
                outcome.sidecar = done.sidecar;
                outcome.unfiltered = done.unfiltered;
                outcome.warnings = done.warnings;
                outcome.parts = done.parts;
                errors.extend(done.errors);
            }
            Err(e) => {
                outcome.unfiltered = only_group;
                errors.push(e.to_string());
            }
        }
    } else {
        errors.push(t!(
            "Recording has no file or metadata",
            "У записи нет файла или метаданных"
        ));
    }
    progress.total.store(0, Ordering::Relaxed);
    outcome.size = path
        .as_ref()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .unwrap_or(0);
    outcome.ok = errors.is_empty();
    if !outcome.ok {
        outcome.error = Some(errors.join("; "));
    }
    let mut g = lock(app);
    g.dump = dump;
    g.dump_phase = DumpPhase::Idle;
    if automatic {
        g.auto_stopped = path;
    }
    g.dump_outcome = Some(outcome.clone());
    outcome
}

/// Повторная обработка уже записанного файла: отбор, сокращение, разбиение. Подходит и
/// для дампов прежних версий, у которых фильтрация не выполнилась.
pub async fn reprocess(
    app: &Shared,
    name: String,
    filter: Option<bool>,
    options: Options,
) -> DumpOutcome {
    reprocess_in(app, &paths::dumps_dir(), name, filter, options).await
}

async fn reprocess_in(
    app: &Shared,
    dir: &Path,
    name: String,
    filter: Option<bool>,
    options: Options,
) -> DumpOutcome {
    let path = match dumpfile::resolve(dir, &name) {
        Ok(path) => path,
        Err(e) => return DumpOutcome::failed(e.to_string()),
    };
    let progress = {
        let mut g = lock(app);
        if g.dump_job.is_some() {
            return DumpOutcome::failed(t!(
                "Another dump is being processed",
                "Уже обрабатывается другой дамп"
            ));
        }
        let current = g.dump_phase != DumpPhase::Idle
            && g.dump
                .path
                .as_deref()
                .is_some_and(|p| Path::new(p).file_name() == path.file_name());
        if current {
            return DumpOutcome::failed(t!(
                "This file is being recorded",
                "Этот файл сейчас записывается"
            ));
        }
        g.dump_job = Some(name.clone());
        g.job_progress.clone()
    };
    let file = path.clone();
    let job = progress.clone();
    let result = tokio::task::spawn_blocking(move || {
        let rec = dumpfile::load(&file, filter)?;
        Ok::<_, std::io::Error>(dumpfile::process(&file, rec, options, &job))
    })
    .await;
    progress.total.store(0, Ordering::Relaxed);
    lock(app).dump_job = None;

    let path_text = path.display().to_string();
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let done = match result {
        Ok(Ok(done)) => done,
        Ok(Err(e)) => return DumpOutcome::failed(e.to_string()),
        Err(e) => return DumpOutcome::failed(e.to_string()),
    };
    DumpOutcome {
        ok: done.errors.is_empty(),
        path: Some(path_text),
        size,
        sidecar: done.sidecar,
        error: (!done.errors.is_empty()).then(|| done.errors.join("; ")),
        warnings: done.warnings,
        unfiltered: done.unfiltered,
        parts: done.parts,
    }
}

/// Соединения за время записи: владелец и домен для подписи пакетов, отбор трафика
/// группы и карта для описания файла.
fn recording_of(
    g: &App,
    m: &mut DumpMeta,
    warnings: Vec<String>,
    capture_complete: bool,
    lost: Losses,
) -> Recording {
    let mut recorded = std::mem::take(&mut m.conns);
    for (key, c) in &g.store.conns {
        if c.last_seen < m.started {
            continue;
        }
        match recorded.get_mut(key) {
            Some(old) => old.update_recording(c),
            None => {
                recorded.insert(*key, c.clone());
            }
        }
    }
    let mut owners = HashMap::with_capacity(recorded.len());
    let mut conns = Vec::new();
    for (k, c) in &recorded {
        if c.last_seen < m.started {
            continue;
        }
        // Общий IP или домен CDN не доказывает принадлежность процессу.
        let keep = dump_owns(m, c);
        owners.insert(
            *k,
            Owner {
                label: annotate::label(c.pname.as_deref(), c.pid, c.domain.as_deref()),
                keep,
            },
        );
        if (keep || !m.only_group) && !c.pid.is_some_and(|p| g.self_pids.contains(&p)) {
            conns.push(ConnRecord::new(c, keep));
        }
    }
    let who = m
        .process
        .as_ref()
        .map(|p| format!("{} [{}]", p.name, p.pid));
    let mut group_pids: Vec<i32> = m.pids.iter().copied().collect();
    group_pids.sort_unstable();
    Recording {
        process: m
            .process
            .as_ref()
            .map(|x| json!({"pid": x.pid, "name": x.name, "cmdline": x.cmdline}))
            .unwrap_or(Value::Null),
        group_pids,
        captured_from: json!(human_time(m.started)),
        captured_until: json!(human_time(state::now_ms())),
        only_process: m.only_group,
        requested: m.only_group,
        comment: dumpfile::section_comment(who.as_deref(), m.only_group),
        conns,
        owners,
        local_ips: g.store.local_ips.clone(),
        warnings,
        capture_complete,
        capture: json!({
            "dropped": lost.dropped,
            "lost_frames": lost.lost_frames,
            "unsupported": lost.unsupported,
        }),
        reprocess: false,
        previous_packets: Value::Null,
        already_compact: false,
    }
}

/// Владелец доказан, если совпал экземпляр процесса. Время старта неизвестно у сокета
/// совсем нового процесса, который успел закрыться до следующего обхода: тогда сверяем PID.
fn dump_owns(m: &DumpMeta, c: &Conn) -> bool {
    c.pid.is_some_and(|pid| match c.owner_started {
        Some(started) => m.instances.contains(&procs::Identity { pid, started }),
        None => m.pids.contains(&pid),
    })
}

fn remember(m: &mut DumpMeta, key: ConnKey, c: &Conn) {
    if c.last_seen < m.started {
        return;
    }
    if let Some(old) = m.conns.get_mut(&key) {
        old.update_recording(c);
    } else if !m.only_group || dump_owns(m, c) {
        if m.conns.len() >= MAX_DUMP_CONNS {
            m.limit_reached = true;
            return;
        }
        m.conns.insert(key, c.clone());
    }
}

/// Перенос изменившихся строк таблицы в сведения записи. Выполняется раз за опрос, а не
/// на каждый пакет: под блокировкой таблицы это задерживало бы разбор и теряло пакеты.
pub fn sync(g: &mut App) {
    let App {
        dump_meta, store, ..
    } = g;
    let Some(m) = dump_meta else {
        return;
    };
    let now = state::now_ms();
    for (key, c) in &store.conns {
        if c.last_seen >= m.synced_at {
            remember(m, *key, c);
        }
    }
    m.synced_at = now;
}

/// Во время записи: копим PID группы (Proton порождает процессы на ходу) и
/// отмечаем, жива ли она. Потомков ищем и от вышедшего корня: их могли переподвесить.
pub fn track(g: &mut App, list: &[ProcInfo]) {
    let Some(m) = g.dump_meta.as_mut() else {
        return;
    };
    if m.process.is_none() {
        return;
    }
    let live: HashMap<i32, &ProcInfo> = list.iter().map(|p| (p.pid, p)).collect();
    let roots: Vec<i32> = m
        .instances
        .iter()
        .filter(|id| live.get(&id.pid).is_some_and(|p| p.identity() == **id))
        .map(|id| id.pid)
        .collect();
    if !roots.is_empty() {
        m.last_alive = state::now_ms();
    }
    for pid in procs::descendants_from(list, roots) {
        if let Some(p) = live.get(&pid).filter(|p| p.started != 0) {
            if !m.instances.contains(&p.identity()) && m.instances.len() >= MAX_DUMP_PROCS {
                m.limit_reached = true;
                return;
            }
            m.instances.insert(p.identity());
            m.pids.insert(pid);
        }
    }
}

#[cfg(test)]
pub mod tests_support {
    use super::*;

    /// Запись трафика выбранного процесса, начатая в самом начале времен.
    pub fn meta(process: ProcInfo) -> DumpMeta {
        DumpMeta {
            pids: HashSet::from([process.pid]),
            instances: HashSet::from([process.identity()]),
            process: Some(process),
            only_group: true,
            options: Options::default(),
            limit_reached: false,
            losses_at_start: Losses::default(),
            started: 0,
            last_alive: 0,
            synced_at: 0,
            conns: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::{app, packet, socket};
    use std::sync::{Arc, Mutex};

    fn only_process(g: &App, conn_key: &ConnKey) -> bool {
        recording_preview(g).owners[conn_key].keep
    }

    /// Сведения записи без изменения приложения: то, что получил бы файл при остановке.
    fn recording_preview(g: &App) -> Recording {
        let m = g.dump_meta.as_ref().unwrap();
        let mut copy = DumpMeta {
            process: m.process.clone(),
            only_group: m.only_group,
            options: m.options,
            pids: m.pids.clone(),
            instances: m.instances.clone(),
            limit_reached: m.limit_reached,
            losses_at_start: m.losses_at_start,
            started: m.started,
            last_alive: m.last_alive,
            synced_at: m.synced_at,
            conns: m.conns.clone(),
        };
        recording_of(g, &mut copy, Vec::new(), true, Losses::default())
    }

    #[test]
    fn selected_process_does_not_include_unknown_traffic_to_a_shared_host() {
        let mut g = app();
        g.store
            .apply_sockets(&[socket(1)], &HashMap::from([(100, &g.procs[0])]));
        g.store.apply_packet(&packet(40000));
        g.store.apply_packet(&packet(40001));
        let rec = recording_preview(&g);
        assert_eq!(rec.owners.values().filter(|o| o.keep).count(), 1);
        assert_eq!(rec.conns.len(), 1);
    }

    #[test]
    fn recording_remembers_proven_flows_after_live_history_is_cleared() {
        let mut g = app();
        g.store
            .apply_sockets(&[socket(1)], &HashMap::from([(100, &g.procs[0])]));
        let key = g.store.apply_packet(&packet(40000));
        sync(&mut g);
        g.store.conns.clear();
        g.store.apply_packet(&packet(40000));
        sync(&mut g);
        assert!(only_process(&g, &key));
        assert_eq!(recording_preview(&g).conns.len(), 1);
    }

    #[test]
    fn recording_does_not_restore_a_disputed_tuple_after_history_clear() {
        let mut g = app();
        let other = ProcInfo {
            pid: 200,
            name: "Other.exe".into(),
            ..g.procs[0].clone()
        };
        g.store
            .apply_sockets(&[socket(1)], &HashMap::from([(100, &g.procs[0])]));
        let key = g.store.apply_packet(&packet(40000));
        sync(&mut g);
        let mut replacement = socket(2);
        replacement.pid = Some(200);
        g.store
            .apply_sockets(&[replacement], &HashMap::from([(200, &other)]));
        g.store.apply_packet(&packet(40000));
        sync(&mut g);
        g.store.conns.clear();
        // Новая запись снова имеет подтвержденного владельца, но весь кортеж
        // за время дампа уже нельзя приписать одному процессу.
        g.store.apply_packet(&packet(40000));
        sync(&mut g);
        assert!(!only_process(&g, &key));
        assert!(recording_preview(&g).conns.is_empty());
    }

    #[test]
    fn late_packet_after_the_socket_closed_keeps_the_flow_in_the_process_dump() {
        let mut g = app();
        g.store
            .apply_sockets(&[socket(1)], &HashMap::from([(100, &g.procs[0])]));
        let key = g.store.apply_packet(&packet(40000));
        sync(&mut g);
        // Игра закрыла сокет, но сервер продолжает слать пакеты на этот порт.
        g.store.apply_sockets(&[], &HashMap::new());
        g.store.apply_packet(&packet(40000));
        sync(&mut g);
        assert!(only_process(&g, &key));
        assert_eq!(recording_preview(&g).conns.len(), 1);
    }

    #[test]
    fn recording_rejects_reused_pid_and_its_new_children() {
        let mut g = app();
        let mut foreign = g.procs[0].clone();
        foreign.started = 2;
        let mut child = foreign.clone();
        child.pid = 101;
        child.ppid = 100;
        track(&mut g, &[foreign.clone(), child]);
        let m = g.dump_meta.as_ref().unwrap();
        assert_eq!(m.instances.len(), 1);
        assert!(!m.pids.contains(&101));
        assert_eq!(m.last_alive, 0);
        g.store
            .apply_sockets(&[socket(1)], &HashMap::from([(100, &foreign)]));
        let k = g.store.apply_packet(&packet(40000));
        sync(&mut g);
        let m = g.dump_meta.as_ref().unwrap();
        assert!(!dump_owns(m, &g.store.conns[&k]));
        assert!(m.conns.is_empty());
        assert!(!only_process(&g, &k));
    }

    #[test]
    fn map_limit_is_explicit_bounded_and_does_not_stop_recording() {
        let mut g = app();
        let key = g.store.apply_packet(&packet(40000));
        let c = g.store.conns[&key].clone();
        let m = g.dump_meta.as_mut().unwrap();
        m.only_group = false;
        for i in 0..MAX_DUMP_CONNS {
            let mut k = key;
            k.lport = (i % 60_000) as u16;
            k.rport = (i / 60_000) as u16;
            remember(m, k, &c);
        }
        assert_eq!(m.conns.len(), MAX_DUMP_CONNS);
        assert!(!m.limit_reached);
        let mut extra = key;
        extra.rport = 60_000;
        remember(m, extra, &c);
        assert!(m.limit_reached);
        assert_eq!(m.conns.len(), MAX_DUMP_CONNS);
        let m = &*m;
        let (warnings, complete) = capture_warnings(m, Losses::default(), true);
        assert_eq!(warnings.len(), 1);
        assert!(!complete);
        g.dump_phase = DumpPhase::Recording;
        assert!(!should_stop(&mut g), "the limit does not end the recording");
    }

    #[test]
    fn losses_become_warnings_and_unknown_types_do_not() {
        let g = app();
        let m = g.dump_meta.as_ref().unwrap();
        let none = Losses {
            unsupported: 100,
            ..Losses::default()
        };
        let (warnings, complete) = capture_warnings(m, none, true);
        assert!(warnings.is_empty() && complete);
        let lost = Losses {
            dropped: 3,
            lost_frames: 2,
            unsupported: 0,
        };
        let (warnings, complete) = capture_warnings(m, lost, false);
        assert_eq!(warnings.len(), 3);
        assert!(!complete);
    }

    #[test]
    fn idle_group_stops_only_a_process_recording() {
        let mut g = app();
        g.dump_phase = DumpPhase::Recording;
        assert!(should_stop(&mut g), "process exited long ago");
        g.dump_meta.as_mut().unwrap().only_group = false;
        assert!(
            !should_stop(&mut g),
            "host recording has no process to wait for"
        );
        g.dump_phase = DumpPhase::Idle;
        g.dump_meta.as_mut().unwrap().only_group = true;
        assert!(!should_stop(&mut g), "nothing is recording");
    }

    #[test]
    fn second_recording_within_a_second_gets_its_own_file() {
        let dir = paths::TestDir::new("unique-path");
        let first = free_dump_path(&dir.0, "demo", "20260101-100000");
        assert!(first.ends_with("demo-20260101-100000.pcapng"));
        std::fs::write(&first, b"x").unwrap();
        let second = free_dump_path(&dir.0, "demo", "20260101-100000");
        assert!(second.ends_with("demo-20260101-100000-2.pcapng"));
        std::fs::write(&second, b"x").unwrap();
        let third = free_dump_path(&dir.0, "demo", "20260101-100000");
        assert!(third.ends_with("demo-20260101-100000-3.pcapng"));
    }

    #[tokio::test]
    async fn start_is_rejected_without_touching_an_active_or_busy_recording() {
        for phase in [
            DumpPhase::Starting,
            DumpPhase::Recording,
            DumpPhase::Finishing,
        ] {
            let mut g = app();
            g.capture_on = true;
            g.dump_phase = phase;
            g.dump.path = Some("demo.pcapng".into());
            g.dump_meta.as_mut().unwrap().started = 123;
            let shared = Arc::new(Mutex::new(g));
            let result = start_dump(shared.clone(), false, Options::default()).await;
            assert_eq!(result["ok"], false);
            let g = lock(&shared);
            assert!(g.dump_phase == phase);
            assert_eq!(g.dump.path.as_deref(), Some("demo.pcapng"));
            assert_eq!(g.dump_meta.as_ref().unwrap().started, 123);
            assert!(g.dump_meta.as_ref().unwrap().only_group);
        }
    }

    #[tokio::test]
    async fn stop_cannot_complete_or_replace_another_operation() {
        for phase in [DumpPhase::Starting, DumpPhase::Finishing, DumpPhase::Idle] {
            let mut g = app();
            g.dump_phase = phase;
            g.dump.path = Some("demo.pcapng".into());
            let shared = Arc::new(Mutex::new(g));
            let result = finish_dump(&shared, false).await;
            assert!(!result.ok);
            assert!(result.error.is_some());
            let g = lock(&shared);
            assert!(g.dump_phase == phase);
            assert_eq!(g.dump.path.as_deref(), Some("demo.pcapng"));
        }
    }

    #[tokio::test]
    async fn start_without_live_capture_returns_an_error() {
        let shared = Arc::new(Mutex::new(app()));
        let started = start_dump(shared.clone(), false, Options::default()).await;
        assert_eq!(started["ok"], false);
        assert!(lock(&shared).dump_phase == DumpPhase::Idle);
    }

    #[tokio::test]
    async fn filtered_start_without_a_running_selection_is_rejected() {
        let mut g = app();
        g.capture_on = true;
        g.selected = Some(200);
        let shared = Arc::new(Mutex::new(g));
        let started = start_dump(shared.clone(), true, Options::default()).await;
        assert_eq!(started["ok"], false);
        assert!(lock(&shared).dump_phase == DumpPhase::Idle);
    }

    #[tokio::test]
    async fn oversized_group_is_rejected_before_starting_capture() {
        let mut g = app();
        g.capture_on = true;
        g.dump_meta = None;
        g.group = (0..MAX_DUMP_PROCS as i32 + 1).collect();
        let app = Arc::new(Mutex::new(g));
        let started = start_dump(app.clone(), true, Options::default()).await;
        assert_eq!(started["ok"], false);
        assert!(lock(&app).dump_phase == DumpPhase::Idle);
        assert!(lock(&app).dump.path.is_none());
    }

    #[tokio::test]
    async fn finalization_waits_for_already_accepted_packets() {
        let metrics = Arc::new(capture::Metrics::default());
        metrics.accepted.store(3, Ordering::Release);
        let applying = metrics.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            applying.processed.store(3, Ordering::Release);
        });
        assert!(wait_packet_accounting(&metrics).await);
        task.await.unwrap();
    }

    #[test]
    fn dump_name_is_cut_by_bytes_at_a_char_boundary() {
        assert_eq!(dump_file_stem("Demo Game/x.exe"), "Demo_Game_x.exe");
        let stem = dump_file_stem(&"игра".repeat(40));
        assert_eq!(stem.len(), 64);
        assert_eq!(stem, "игра".repeat(8));
        let stem = dump_file_stem(&format!("a{}", "я".repeat(40)));
        assert_eq!(stem.len(), 63);
    }

    #[tokio::test]
    async fn reprocessing_rejects_names_outside_the_dump_folder() {
        let dir = paths::TestDir::new("reprocess-names");
        let shared = Arc::new(Mutex::new(app()));
        for name in ["../demo.pcapng", "demo.json", ""] {
            let done = reprocess_in(&shared, &dir.0, name.into(), None, Options::default()).await;
            assert!(!done.ok && done.error.is_some(), "{name}");
        }
        assert!(lock(&shared).dump_job.is_none());
    }

    #[tokio::test]
    async fn file_being_recorded_is_not_reprocessed() {
        let dir = paths::TestDir::new("reprocess-current");
        let file = dir.0.join("demo.pcapng");
        std::fs::write(&file, b"recording").unwrap();
        let mut g = app();
        g.dump_phase = DumpPhase::Recording;
        g.dump.path = Some(file.display().to_string());
        let shared = Arc::new(Mutex::new(g));
        let done = reprocess_in(
            &shared,
            &dir.0,
            "demo.pcapng".into(),
            None,
            Options::default(),
        )
        .await;
        assert!(!done.ok && done.error.is_some());
        assert_eq!(std::fs::read(&file).unwrap(), b"recording");
        assert!(lock(&shared).dump_job.is_none());
    }

    #[tokio::test]
    async fn second_job_waits_for_the_first_one() {
        let dir = paths::TestDir::new("reprocess-busy");
        let file = dir.0.join("demo.pcapng");
        std::fs::write(&file, b"untouched").unwrap();
        let mut g = app();
        g.dump_job = Some("other.pcapng".into());
        let shared = Arc::new(Mutex::new(g));
        let done = reprocess_in(
            &shared,
            &dir.0,
            "demo.pcapng".into(),
            None,
            Options::default(),
        )
        .await;
        assert!(!done.ok && done.error.is_some());
        assert_eq!(std::fs::read(&file).unwrap(), b"untouched");
        assert_eq!(lock(&shared).dump_job.as_deref(), Some("other.pcapng"));
    }
}
