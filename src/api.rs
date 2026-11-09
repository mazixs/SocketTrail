//! HTTP API локального окна. Сервер слушает только 127.0.0.1, запросы проходят проверку
//! Host и Origin.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Query, Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::{App, Shared, lock};
use crate::dumpfile::{self, Options, SplitMode};
use crate::localtime::human_time;
use crate::procs::ProcInfo;
use crate::query::{self, Column, Filters, Scope, Sort, View};
use crate::recording::{self, DumpOutcome, DumpPhase};
use crate::state::{self, Conn};
use crate::{alive, i18n, paths, report, window};

pub fn router(app: Shared, alive: Arc<alive::Alive>, port: u16) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/alive", {
            let a = alive.clone();
            get(move || async move { alive::stream(a) })
        })
        .route(window::UI_PATH, get(index))
        .route("/api/ping", get(api_ping))
        .route("/api/procs", get(api_procs))
        .route("/api/state", get(api_state))
        .route("/api/facets", get(api_facets))
        .route("/api/select", post(api_select))
        .route("/api/dump/start", post(api_dump_start))
        .route("/api/dump/stop", post(api_dump_stop))
        .route("/api/clear", post(api_clear))
        .route("/api/dumps", get(api_dumps))
        .route("/api/dumps/summary", get(api_dump_summary))
        .route("/api/dumps/process", post(api_dump_process))
        .route("/api/reveal", post(api_reveal))
        .route("/api/export", get(api_export))
        .route("/api/elevate", post(api_elevate))
        .route("/api/lang", post(api_lang))
        .layer(axum::middleware::from_fn(move |req, next| {
            guard(port, req, next)
        }))
        .with_state(app)
}

/// Защита локального API от чужих страниц в браузере. Проверка Host отсекает
/// DNS rebinding (чужой домен, указывающий на 127.0.0.1), проверка Origin -
/// запросы со сторонних сайтов, которые браузер отправляет без спроса (CSRF).
async fn guard(port: u16, req: Request, next: Next) -> Response {
    if request_allowed(port, req.method(), req.headers()) {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "forbidden").into_response()
    }
}

/// Host защищает от DNS rebinding, Origin - от POST с чужих страниц. GET с чужого
/// сайта (`<img src=.../api/alive>`, ссылка на `/api/export`) отсекает
/// Sec-Fetch-Site: браузер ставит его на запросы к 127.0.0.1 и localhost.
fn request_allowed(port: u16, method: &Method, headers: &axum::http::HeaderMap) -> bool {
    let allowed = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    let value = |name: header::HeaderName| headers.get(name).and_then(|h| h.to_str().ok());
    let host_ok = value(header::HOST).is_some_and(|h| allowed.iter().any(|a| a == h));
    let origin_ok = method == Method::GET
        || match value(header::ORIGIN) {
            None => true,
            Some(o) => allowed.iter().any(|a| o == format!("http://{a}")),
        };
    let site_ok = !matches!(
        value(header::HeaderName::from_static("sec-fetch-site")),
        Some("cross-site" | "same-site")
    );
    host_ok && origin_ok && site_ok
}

/// Перезапуск с правами администратора. Новый экземпляр ждет нашего выхода,
/// занимает тот же порт, и открытое окно продолжает работать с ним.
async fn api_elevate(State(app): State<Shared>) -> impl IntoResponse {
    #[cfg(windows)]
    {
        let (port, iface, quit) = {
            let g = lock(&app);
            (g.port, g.iface.clone(), g.quit.clone())
        };
        let mut args = format!(
            "--port {port} --no-open --adopt --lang {} --wait-pid {}",
            i18n::code(),
            std::process::id()
        );
        if iface != "any" {
            args += &format!(" -i \"{iface}\"");
        }
        let r = tokio::task::spawn_blocking(move || crate::elevate::relaunch(&args))
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
        match r {
            Ok(()) => {
                let _ = quit.send(i18n::tr(
                    "restarting as administrator",
                    "перезапуск от имени администратора",
                ));
                Json(json!({ "ok": true }))
            }
            Err(e) => Json(json!({ "ok": false, "error": e })),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Json(json!({ "ok": false, "error": t!("Windows only", "только для Windows") }))
    }
}

/// Язык и система подставляются в разметку сразу, чтобы окно не мигало: ни английским
/// перед русским, ни кнопками, которых на этой системе нет.
async fn index() -> impl IntoResponse {
    let os = if cfg!(windows) { "windows" } else { "linux" };
    Html(
        include_str!("../ui/index.html")
            .replacen("__LANG__", i18n::code(), 1)
            .replacen("__OS__", os, 1),
    )
}

#[derive(Deserialize)]
struct LangBody {
    lang: String,
}

async fn api_lang(Json(b): Json<LangBody>) -> impl IntoResponse {
    let ok = i18n::set(&b.lang);
    if ok {
        i18n::save();
    }
    Json(json!({ "ok": ok, "lang": i18n::code() }))
}

/// Метка своего экземпляра: по ней повторный запуск понимает, что окно уже есть.
async fn api_ping() -> impl IntoResponse {
    Json(json!({ "app": "sockettrail", "version": env!("CARGO_PKG_VERSION") }))
}

#[derive(Deserialize)]
struct ProcsQuery {
    /// active | proton | all
    #[serde(default)]
    filter: String,
    #[serde(default)]
    q: String,
    #[serde(default)]
    show_self: Option<u8>,
}

async fn api_procs(State(app): State<Shared>, Query(q): Query<ProcsQuery>) -> impl IntoResponse {
    let g = lock(&app);
    let now = state::now_ms();

    // Живые соединения по процессам - показываются счетчиком в дереве.
    let mut live: HashMap<i32, usize> = HashMap::new();
    for c in g.store.conns.values() {
        if !c.closed
            && c.scope == "public"
            && let Some(pid) = c.pid
        {
            *live.entry(pid).or_insert(0) += 1;
        }
    }

    let show_self = q.show_self.unwrap_or(0) == 1;
    let needle = q.q.to_lowercase();
    let want = |p: &ProcInfo| -> bool {
        if !show_self && g.self_pids.contains(&p.pid) {
            return false;
        }
        let by_filter = match q.filter.as_str() {
            "proton" => p.proton,
            "all" => true,
            _ => g.is_active(p.pid, now),
        };
        let by_query = needle.is_empty()
            || p.name.to_lowercase().contains(&needle)
            || p.pid.to_string().contains(&needle)
            || p.cmdline.to_lowercase().contains(&needle);
        by_filter && by_query
    };

    // Отобранные процессы плюс их предки: без предков дерево рассыпается на
    // отдельные ветки и связь "игра - wineserver - GameThread" теряется.
    // Выбранный процесс в списке всегда, иначе выбор нельзя было бы снять.
    let by_pid: HashMap<i32, &ProcInfo> = g.procs.iter().map(|p| (p.pid, p)).collect();
    let mut keep: HashSet<i32> = HashSet::new();
    let mut matched: HashSet<i32> = HashSet::new();
    for p in g
        .procs
        .iter()
        .filter(|p| want(p) || g.selected == Some(p.pid))
    {
        if want(p) {
            matched.insert(p.pid);
        }
        keep.insert(p.pid);
        let mut cur = p.ppid;
        let mut guard = 0;
        while cur > 1 && guard < 64 {
            guard += 1;
            if !keep.insert(cur) {
                break;
            }
            match by_pid.get(&cur) {
                Some(parent) => cur = parent.ppid,
                None => break,
            }
        }
    }

    let list: Vec<_> = g
        .procs
        .iter()
        .filter(|p| keep.contains(&p.pid))
        .map(|p| {
            json!({
                "pid": p.pid,
                "ppid": p.ppid,
                "name": p.name,
                "comm": p.comm,
                "cmdline": p.cmdline,
                "proton": p.proton,
                "active": g.is_active(p.pid, now),
                "conns": live.get(&p.pid).copied().unwrap_or(0),
                "matched": matched.contains(&p.pid),
                "own": g.self_pids.contains(&p.pid),
            })
        })
        .collect();

    Json(json!({
        "procs": list,
        "selected": g.selected,
        "selected_name": g.selected_name,
        "selected_gone": g.selected_gone,
        "total": g.procs.len(),
    }))
}

/// Параметры таблицы: общие для строк, фасетов и выгрузки, чтобы отчет и копия всегда
/// совпадали с тем, что на экране.
#[derive(Default, Deserialize)]
#[serde(default)]
struct TableQuery {
    scope: String,
    view: String,
    q: String,
    proto: String,
    show_local: Option<u8>,
    show_self: Option<u8>,
    sort: String,
    dir: String,
    page: Option<usize>,
    limit: Option<usize>,
    /// JSON: {"state":["ESTABLISHED"],"dom":["example.com"]}
    filters: String,
    /// столбец фасета
    column: String,
    /// формат выгрузки
    format: String,
}

impl TableQuery {
    fn scope<'a>(&self, g: &'a App, show_local_default: bool) -> Scope<'a> {
        let group = (self.scope != "host" && g.selected.is_some())
            .then(|| g.group.iter().copied().collect());
        Scope {
            group,
            self_pids: &g.self_pids,
            ui_port: g.port,
            proto: query::proto_param(&self.proto),
            show_local: self.show_local.map_or(show_local_default, |v| v == 1),
            show_self: self.show_self.unwrap_or(0) == 1,
            text: self.q.clone(),
        }
    }

    fn filters(&self) -> query::Compiled {
        Filters::from_json(&self.filters).compile()
    }
}

/// Значение limit по умолчанию: столько строк показывается без заметной задержки.
const PAGE_DEFAULT: usize = 200;
const PAGE_MAX: usize = 5000;
const FACET_LIMIT: usize = 2000;

async fn api_state(State(app): State<Shared>, Query(q): Query<TableQuery>) -> impl IntoResponse {
    let (mut response, rows, targets) = {
        let g = lock(&app);
        let scope = q.scope(&g, false);
        let filters = q.filters();
        let view = View::parse(&q.view);
        let sort = Sort::parse(&q.sort, &q.dir);
        let limit = q.limit.unwrap_or(PAGE_DEFAULT).clamp(1, PAGE_MAX);
        let want_page = q.page.unwrap_or(0);

        let mut picked = query::select(g.store.conns.values(), &scope, &filters, None);
        let matched = picked.len();
        let attributed = picked.iter().filter(|c| c.pid.is_some()).count();
        // Только строки страницы: сериализовать лучше уже вне блокировки.
        let (rows, targets, total, page) = if view == View::List {
            query::sort_conns(&mut picked, sort);
            let (page, range) = query::page_range(matched, want_page, limit);
            let head: Vec<Conn> = picked[range].iter().map(|c| (*c).clone()).collect();
            (head, Vec::new(), matched, page)
        } else {
            let mut groups = query::group(&picked, view);
            query::sort_groups(&mut groups, sort);
            let total = groups.len();
            let (page, range) = query::page_range(total, want_page, limit);
            let head: Vec<query::Group> = groups.drain(range).collect();
            (Vec::new(), head, total, page)
        };
        let losses = g.capture_metrics.losses();
        let response = json!({
            "stats": {
                "matched": matched,
                "stored": g.store.conns.len(),
                "attributed": attributed,
                "packets": g.store.packets_seen,
                "capture": g.capture_on,
                "dropped": losses.dropped,
                "lost_frames": losses.lost_frames,
                "unsupported": losses.unsupported,
                "capture_hint": g.capture_hint.as_ref().map(|t| t.get()),
                "capture_how": g.capture_how,
                "elevate": g.can_elevate,
                "iface": g.iface,
            },
            "page": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": total.div_ceil(limit).max(1),
            },
            "dump": dump_status(&g),
            "group": g.group,
            "selected": g.selected,
            "selected_name": g.selected_name,
            "selected_gone": g.selected_gone,
        });
        (response, rows, targets)
    };
    response["conns"] = json!(rows);
    response["targets"] = json!(targets);
    Json(response)
}

fn dump_status(g: &App) -> Value {
    json!({
        "running": g.dump.is_running(),
        "busy": matches!(g.dump_phase, DumpPhase::Starting | DumpPhase::Finishing),
        "result": g.dump_outcome,
        "path": g.dump.path,
        "started": g.dump.started_ms,
        "only": g.dump_meta.as_ref().is_some_and(|m| m.only_group),
        "auto_stopped": g.auto_stopped,
        "progress": g.dump_progress.percent(),
        "job": g.dump_job,
        "job_progress": g.job_progress.percent(),
    })
}

/// Значения столбца для списка отбора. Собственный отбор столбца не применяется, иначе
/// после выбора одного значения остальные исчезли бы из списка.
async fn api_facets(State(app): State<Shared>, Query(q): Query<TableQuery>) -> impl IntoResponse {
    let Some(column) = Column::parse(&q.column) else {
        return Json(json!({"column": q.column, "values": [], "total": 0, "truncated": false}));
    };
    let mut values = {
        let g = lock(&app);
        let scope = q.scope(&g, false);
        let filters = q.filters();
        let rows = query::select(g.store.conns.values(), &scope, &filters, Some(column));
        query::facets(&rows, column)
    };
    let total = values.len();
    values.truncate(FACET_LIMIT);
    Json(json!({
        "column": q.column,
        "values": values,
        "total": total,
        "truncated": total > FACET_LIMIT,
    }))
}

#[derive(Deserialize)]
struct SelectBody {
    pid: Option<i32>,
}

async fn api_select(State(app): State<Shared>, Json(b): Json<SelectBody>) -> impl IntoResponse {
    let mut g = lock(&app);
    let process = b
        .pid
        .and_then(|pid| g.procs.iter().find(|p| p.pid == pid).cloned());
    g.selected = b.pid;
    g.selected_gone = false;
    g.selected_instance = process.as_ref().map(ProcInfo::identity);
    g.selected_name = process.map(|p| p.name);
    g.group = match b.pid {
        Some(pid) => crate::procs::descendants(&g.procs, pid),
        None => Vec::new(),
    };
    Json(json!({ "ok": true, "group": g.group }))
}

#[derive(Deserialize)]
struct DumpBody {
    #[serde(default)]
    filtered: bool,
    #[serde(default)]
    compact: bool,
    #[serde(default)]
    split: SplitMode,
}

async fn api_dump_start(State(app): State<Shared>, Json(b): Json<DumpBody>) -> impl IntoResponse {
    let options = Options {
        compact: b.compact,
        split: b.split,
    };
    let result = tokio::spawn(recording::start_dump(app, b.filtered, options))
        .await
        .unwrap_or_else(|e| json!({"ok": false, "error": e.to_string()}));
    Json(result)
}

async fn api_dump_stop(State(app): State<Shared>) -> impl IntoResponse {
    let outcome = tokio::spawn(async move { recording::finish_dump(&app, false).await })
        .await
        .unwrap_or_else(|e| DumpOutcome::failed(e.to_string()));
    Json(outcome)
}

/// Список уже собранных дампов. Каталог называется так же, как репозиторий
/// проекта, и спутать их легко - поэтому путь показываем прямо в окне.
async fn api_dumps(State(app): State<Shared>) -> impl IntoResponse {
    let dir = paths::dumps_dir();
    let (job, current) = {
        let g = lock(&app);
        let current = (g.dump_phase != DumpPhase::Idle)
            .then(|| g.dump.path.clone())
            .flatten();
        (g.dump_job.clone(), current)
    };
    let scan = dir.clone();
    let mut files = tokio::task::spawn_blocking(move || dumpfile::list(&scan))
        .await
        .unwrap_or_default();
    if let Some(current) = current {
        let current = std::path::Path::new(&current);
        for f in &mut files {
            let same = f["name"]
                .as_str()
                .is_some_and(|n| Some(std::ffi::OsStr::new(n)) == current.file_name());
            if same {
                f["recording"] = json!(true);
            }
        }
    }
    Json(json!({ "dir": dir.to_string_lossy(), "files": files, "job": job }))
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct NameQuery {
    name: String,
}

async fn api_dump_summary(Query(q): Query<NameQuery>) -> impl IntoResponse {
    let result = tokio::task::spawn_blocking(move || {
        let path = dumpfile::resolve(&paths::dumps_dir(), &q.name)?;
        dumpfile::summary(&path)
    })
    .await;
    match result {
        Ok(Ok(summary)) => Json(json!({"ok": true, "summary": summary})),
        Ok(Err(e)) => Json(json!({"ok": false, "error": e.to_string()})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
struct ProcessBody {
    name: String,
    /// Только соединения процесса. Без значения состав файла не меняется.
    #[serde(default)]
    filter: Option<bool>,
    #[serde(default)]
    compact: bool,
    #[serde(default)]
    split: SplitMode,
}

async fn api_dump_process(
    State(app): State<Shared>,
    Json(b): Json<ProcessBody>,
) -> impl IntoResponse {
    let options = Options {
        compact: b.compact,
        split: b.split,
    };
    let outcome =
        tokio::spawn(async move { recording::reprocess(&app, b.name, b.filter, options).await })
            .await
            .unwrap_or_else(|e| DumpOutcome::failed(e.to_string()));
    Json(outcome)
}

/// Открытие каталога дампов в файловом менеджере; для дампа с частями - каталога частей.
async fn api_reveal(Query(q): Query<NameQuery>) -> impl IntoResponse {
    let dir = paths::dumps_dir();
    let _ = std::fs::create_dir_all(&dir);
    let target = dumpfile::resolve(&dir, &q.name)
        .ok()
        .and_then(|path| dumpfile::reveal_target(&path))
        .unwrap_or(dir);
    let text = target.to_string_lossy().into_owned();
    let ok = window::open_default(&text);
    Json(json!({ "ok": ok, "dir": text }))
}

async fn api_clear(State(app): State<Shared>) -> impl IntoResponse {
    let mut g = lock(&app);
    // Идущая запись не должна потерять то, что еще не успела сохранить.
    recording::sync(&mut g);
    g.store.conns.clear();
    g.store.packets_seen = 0;
    Json(json!({ "ok": true }))
}

async fn api_export(State(app): State<Shared>, Query(q): Query<TableQuery>) -> impl IntoResponse {
    let g = lock(&app);
    let scope = q.scope(&g, true);
    let filters = q.filters();
    let mut picked = query::select(g.store.conns.values(), &scope, &filters, None);
    let only_selected = scope.group.is_some();
    // Без выбранной сортировки отчет читается как журнал, от старых записей к новым.
    let sort = if q.sort.is_empty() {
        Sort::parse("time", "asc")
    } else {
        Sort::parse(&q.sort, &q.dir)
    };
    query::sort_conns(&mut picked, sort);
    let conns: Vec<Conn> = picked.iter().map(|c| (*c).clone()).collect();
    drop(picked);
    let pname = match g.selected.filter(|_| only_selected) {
        Some(pid) => g.procs.iter().find(|p| p.pid == pid).map_or_else(
            || format!("pid {pid}"),
            |p| format!("{} (pid {})", p.name, p.pid),
        ),
        None => t!("whole host", "весь хост"),
    };
    let group = if only_selected {
        g.group.clone()
    } else {
        Vec::new()
    };
    drop(scope);
    drop(g);
    let now = human_time(state::now_ms());

    if q.format == "html" {
        let html = report::render(
            &t!(
                "Network connections: {pname}",
                "Сетевые соединения: {pname}"
            ),
            &now,
            &conns,
        );
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"sockettrail-report.html\"",
                ),
            ],
            html,
        );
    }

    let body = serde_json::to_string_pretty(&json!({
        "generated": now,
        "process": pname,
        "group": group,
        "conns": conns,
    }))
    .unwrap_or_default();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"sockettrail.json\"",
            ),
        ],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::{app, packet, socket};
    use crate::pcap::Packet;
    use crate::sockets::Proto;
    use std::sync::Mutex;

    #[test]
    fn guard_rejects_foreign_hosts_origins_and_cross_site_reads() {
        let req = |method: Method, pairs: &[(&'static str, &str)]| {
            let mut h = axum::http::HeaderMap::new();
            for (k, v) in pairs {
                h.insert(*k, v.parse().unwrap());
            }
            request_allowed(8787, &method, &h)
        };
        let host = ("host", "127.0.0.1:8787");
        assert!(req(Method::GET, &[host]));
        assert!(req(
            Method::GET,
            &[("host", "localhost:8787"), ("sec-fetch-site", "none")]
        ));
        assert!(req(Method::GET, &[host, ("sec-fetch-site", "same-origin")]));
        assert!(!req(Method::GET, &[("host", "attacker.example:8787")]));
        assert!(!req(Method::GET, &[]));
        assert!(!req(Method::GET, &[host, ("sec-fetch-site", "cross-site")]));
        assert!(!req(Method::GET, &[host, ("sec-fetch-site", "same-site")]));
        assert!(req(
            Method::POST,
            &[host, ("origin", "http://127.0.0.1:8787")]
        ));
        assert!(!req(
            Method::POST,
            &[host, ("origin", "http://127.0.0.1:9000")]
        ));
        assert!(!req(
            Method::POST,
            &[host, ("origin", "https://attacker.example")]
        ));
    }

    fn with_selection(selected: bool) -> Shared {
        let mut g = app();
        if !selected {
            g.selected = None;
            g.selected_instance = None;
            g.group.clear();
        }
        g.store
            .apply_sockets(&[socket(1)], &HashMap::from([(100, &g.procs[0])]));
        g.store.apply_packet(&packet(40000));
        g.store.apply_packet(&packet(40001));
        Arc::new(Mutex::new(g))
    }

    async fn state_of(app: &Shared, q: TableQuery) -> Value {
        let body = api_state(State(app.clone()), Query(q))
            .await
            .into_response()
            .into_body();
        serde_json::from_slice(&axum::body::to_bytes(body, usize::MAX).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn selected_process_view_shows_only_its_connections() {
        let shared = with_selection(true);
        let own = state_of(
            &shared,
            TableQuery {
                show_local: Some(1),
                ..TableQuery::default()
            },
        )
        .await;
        assert_eq!(own["stats"]["matched"], 1);
        assert_eq!(own["selected"], 100);
        assert_eq!(own["selected_name"], "DemoGame.exe");
        let host = state_of(
            &shared,
            TableQuery {
                scope: "host".into(),
                show_local: Some(1),
                ..TableQuery::default()
            },
        )
        .await;
        assert_eq!(host["stats"]["matched"], 2);
    }

    #[tokio::test]
    async fn pages_and_limits_of_the_table_are_reported() {
        let mut g = app();
        g.selected = None;
        g.group.clear();
        for port in 40000..40005 {
            g.store.apply_packet(&packet(port));
        }
        let shared = Arc::new(Mutex::new(g));
        let q = |page| TableQuery {
            limit: Some(2),
            page: Some(page),
            show_local: Some(1),
            ..TableQuery::default()
        };
        let first = state_of(&shared, q(0)).await;
        assert_eq!(first["conns"].as_array().unwrap().len(), 2);
        assert_eq!(first["page"]["pages"], 3);
        assert_eq!(first["page"]["total"], 5);
        let last = state_of(&shared, q(2)).await;
        assert_eq!(last["conns"].as_array().unwrap().len(), 1);
        let beyond = state_of(&shared, q(99)).await;
        assert_eq!(beyond["page"]["page"], 2);
        assert_eq!(beyond["conns"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn filters_and_groups_come_through_the_query() {
        let mut g = app();
        g.selected = None;
        g.group.clear();
        let a = g.store.apply_packet(&packet(40000));
        let b = g.store.apply_packet(&Packet {
            proto: Proto::Tcp,
            dst: "203.0.113.5".parse().unwrap(),
            dport: 443,
            ..packet(40001)
        });
        g.store.conns.get_mut(&a).unwrap().domain = Some("api.example.com".into());
        g.store.conns.get_mut(&b).unwrap().domain = Some("cdn.example.net".into());
        let shared = Arc::new(Mutex::new(g));

        let filtered = state_of(
            &shared,
            TableQuery {
                filters: r#"{"dom":["example.com"]}"#.into(),
                show_local: Some(1),
                ..TableQuery::default()
            },
        )
        .await;
        assert_eq!(filtered["stats"]["matched"], 1);
        assert_eq!(filtered["conns"][0]["domain"], "api.example.com");

        let by_domain = state_of(
            &shared,
            TableQuery {
                view: "domain".into(),
                sort: "dom".into(),
                dir: "asc".into(),
                show_local: Some(1),
                ..TableQuery::default()
            },
        )
        .await;
        assert_eq!(by_domain["page"]["total"], 2);
        assert_eq!(by_domain["targets"][0]["key"], "example.com");

        let body = api_facets(
            State(shared.clone()),
            Query(TableQuery {
                column: "dom".into(),
                filters: r#"{"dom":["example.com"]}"#.into(),
                show_local: Some(1),
                ..TableQuery::default()
            }),
        )
        .await
        .into_response()
        .into_body();
        let facets: Value =
            serde_json::from_slice(&axum::body::to_bytes(body, usize::MAX).await.unwrap()).unwrap();
        assert_eq!(facets["values"].as_array().unwrap().len(), 2);
    }

    async fn export_json(app: &Shared, q: TableQuery) -> Value {
        let body = api_export(State(app.clone()), Query(q))
            .await
            .into_response()
            .into_body();
        serde_json::from_slice(&axum::body::to_bytes(body, usize::MAX).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn host_export_is_not_titled_with_the_selected_process() {
        let shared = Arc::new(Mutex::new(app()));
        let host = export_json(
            &shared,
            TableQuery {
                format: "json".into(),
                scope: "host".into(),
                ..TableQuery::default()
            },
        )
        .await;
        assert_eq!(host["process"], t!("whole host", "весь хост"));
        assert_eq!(host["group"], json!([]));
        let own = export_json(
            &shared,
            TableQuery {
                format: "json".into(),
                scope: "proc".into(),
                ..TableQuery::default()
            },
        )
        .await;
        assert_eq!(own["process"], "DemoGame.exe (pid 100)");
        assert_eq!(own["group"], json!([100]));
    }

    #[tokio::test]
    async fn export_follows_the_same_filters_as_the_table() {
        let shared = with_selection(false);
        let all = export_json(
            &shared,
            TableQuery {
                scope: "host".into(),
                ..TableQuery::default()
            },
        )
        .await;
        assert_eq!(all["conns"].as_array().unwrap().len(), 2);
        let one = export_json(
            &shared,
            TableQuery {
                scope: "host".into(),
                q: "40000".into(),
                filters: r#"{"port":["443"]}"#.into(),
                ..TableQuery::default()
            },
        )
        .await;
        assert_eq!(one["conns"].as_array().unwrap().len(), 0);
        let one = export_json(
            &shared,
            TableQuery {
                scope: "host".into(),
                filters: r#"{"port":["27015"],"state":["NEW"]}"#.into(),
                ..TableQuery::default()
            },
        )
        .await;
        assert_eq!(one["conns"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn clearing_history_keeps_what_the_recording_already_proved() {
        let shared = with_selection(true);
        {
            let mut g = lock(&shared);
            let meta = g.dump_meta.as_mut().unwrap();
            meta.started = 0;
        }
        let _ = api_clear(State(shared.clone())).await.into_response();
        let g = lock(&shared);
        assert!(g.store.conns.is_empty());
        assert_eq!(g.dump_meta.as_ref().unwrap().conns.len(), 1);
    }

    #[tokio::test]
    async fn process_list_always_contains_the_selected_process() {
        let shared = with_selection(true);
        let body = api_procs(
            State(shared),
            Query(ProcsQuery {
                filter: "proton".into(),
                q: String::new(),
                show_self: None,
            }),
        )
        .await
        .into_response()
        .into_body();
        let v: Value =
            serde_json::from_slice(&axum::body::to_bytes(body, usize::MAX).await.unwrap()).unwrap();
        let list = v["procs"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["pid"], 100);
        assert_eq!(list[0]["matched"], false);
    }
}
