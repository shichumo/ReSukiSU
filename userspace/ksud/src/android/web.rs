// WebKSU 嵌入式网页管理器（独立运行版，无需任何模块）
//
// 编译进 ksud：开机 service / boot-completed 阶段自动拉起（ensure_started），
// 也可手动前台运行：`ksud web`。
// 接口与模块版 busybox httpd CGI 完全同构，网页端无需任何修改：
//   GET  /                          内嵌单文件 Web UI
//   GET/POST /cgi-bin/api?op=ping   探活
//   POST /cgi-bin/api?op=exec       body=base64(命令)  → X-E=errno X-S=stderr(URL-safe b64) body=stdout
//   POST /cgi-bin/api?op=write&p=…&m=w|a  body=base64(内容)（仅允许 /data/ 下）
//   GET  /cgi-bin/api?op=suctl&a=<info|list|granted|grant|revoke|get>&p=<包名>&u=<uid>
//        授权名单专用端点：服务端校验参数并自行拼命令，只有它能拿到 suctl 的 WKSU_TOKEN
// 配置 /data/adb/webksu.conf（PORT/BIND/TOKEN/WEB_ENABLED，与模块版同格式），
// PID 写入 /data/adb/webksu/httpd.pid，带令牌的入口地址写入 /data/adb/webksu/entry.txt（600）。
// 所有 /cgi-bin/api 请求都必须带令牌（conf TOKEN，缺省时使用 suctl 令牌文件）。
// 纯 std 实现，不引入任何新依赖。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use log::{error, info, warn};
use rust_embed::RustEmbed;

use crate::android::utils;

#[derive(RustEmbed)]
#[folder = "webroot/"]
struct WebAssets;

/* webksu_suctl（Root 授权管理工具）也内嵌进 ksud，开机自动部署 —— 完全不依赖模块 */
#[derive(RustEmbed)]
#[folder = "suctl/"]
struct SuctlAssets;

const CONF_PATH: &str = "/data/adb/webksu.conf";
const PID_FILE: &str = "/data/adb/webksu/httpd.pid";
const ENTRY_FILE: &str = "/data/adb/webksu/entry.txt";
const SUCTL_DST: &str = "/data/adb/webksu/webksu_suctl";
/* 外部网页覆盖：存在则优先于内嵌页面 —— 网页更新只需替换此文件，无需重编译/重刷 ksud */
const EXT_INDEX: &str = "/data/adb/webksu/webroot/index.html";
const MAX_BODY: usize = 64 * 1024 * 1024;
const COMMON_HEADERS: &str = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: X-Token,Content-Type\r\nAccess-Control-Allow-Methods: POST,GET,OPTIONS\r\nAccess-Control-Expose-Headers: X-E,X-S\r\nCache-Control: no-store\r\nConnection: close\r\n";

static STARTED: AtomicBool = AtomicBool::new(false);

/* 开机钩子调用：默认启用（独立版就是网页管理器）；webksu.conf 里写 WEB_ENABLED=0 可退回普通 ksud */
pub fn ensure_started() {
    if !read_conf().web_enabled {
        return;
    }
    start_bg();
}

/* 后台守护方式启动（幂等：本进程只 fork 一次，端口占用由 bind 报错兜底） */
pub fn start_bg() {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let is_child = match utils::create_daemon_with(false, || Ok(())) {
        Ok(v) => v,
        Err(e) => {
            error!("[webksu] fork web daemon failed: {e:#}");
            return;
        }
    };
    if !is_child {
        info!("[webksu] web daemon forked");
        return; // 父进程继续执行模块脚本/命令
    }
    // 守护子进程：常驻运行嵌入式 Web 服务器
    if let Err(e) = serve() {
        error!("[webksu] embedded web server exited: {e:#}");
    }
    std::process::exit(0);
}

/* 带令牌的入口地址：优先 conf TOKEN，其次 suctl 令牌文件 */
fn entry_url() -> Option<String> {
    let c = read_conf();
    let tok = if c.token.trim().is_empty() {
        std::fs::read_to_string(TOKEN_FILE).unwrap_or_default().trim().to_string()
    } else {
        c.token.trim().to_string()
    };
    if tok.is_empty() {
        return None;
    }
    let host = if c.bind.contains(':') { format!("[{}]", c.bind) } else { c.bind.clone() };
    Some(format!("http://{host}:{}/?t={tok}", c.port))
}

/* `ksud web enable/disable/start/stop/status`：供管理器 App 开关与 adb 使用 */
pub fn control(op: &str) -> Result<()> {
    match op {
        "enable" => {
            set_web_enabled(true)?;
            println!("web manager enabled (persists across reboots)");
            start_bg();
            match entry_url() {
                Some(u) => println!("started: {u}"),
                None => println!("started: http://127.0.0.1:{}", read_conf().port),
            }
        }
        "disable" => {
            set_web_enabled(false)?;
            stop_server();
            println!("web manager disabled and stopped");
        }
        "start" => {
            start_bg();
            match entry_url() {
                Some(u) => println!("started: {u}"),
                None => println!("started: http://127.0.0.1:{}", read_conf().port),
            }
        }
        "stop" => {
            stop_server();
            println!("stopped");
        }
        "status" => {
            let c = read_conf();
            let running = std::fs::read_to_string(PID_FILE)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .map(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
                .unwrap_or(false);
            println!("enabled={} running={} port={}", c.web_enabled as u8, running as u8, c.port);
            if running {
                if let Ok(u) = std::fs::read_to_string(ENTRY_FILE) {
                    println!("entry: {}", u.trim());
                }
            }
        }
        other => bail!("unknown web op: {other}"),
    }
    Ok(())
}

fn set_web_enabled(on: bool) -> Result<()> {
    let mut lines: Vec<String> = std::fs::read_to_string(CONF_PATH)
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .filter(|l| !l.trim().starts_with("WEB_ENABLED"))
        .collect();
    lines.push(format!("WEB_ENABLED={}", if on { 1 } else { 0 }));
    let mut out = lines.join("\n");
    out.push('\n');
    std::fs::create_dir_all("/data/adb/webksu").ok();
    std::fs::write(CONF_PATH, out).with_context(|| format!("write {CONF_PATH}"))?;
    Ok(())
}

fn stop_server() {
    if let Ok(pid) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid.trim().parse::<u32>() {
            let _ = Command::new("kill").arg(pid.to_string()).status();
        }
    }
    let _ = std::fs::remove_file(PID_FILE);
}

/* `ksud web`：前台运行 */
pub fn serve_blocking() -> Result<()> {
    if STARTED.swap(true, Ordering::SeqCst) {
        bail!("webksu already running in this ksud process");
    }
    serve()
}

struct Conf {
    port: u16,
    bind: String,
    token: String,
    web_enabled: bool,
    copy_token: bool,
}

/* 开机部署内嵌的 webksu_suctl（Root 授权工具），幂等：每次启动都覆盖为内嵌版本 */
fn deploy_suctl() {
    if let Some(b) = SuctlAssets::get("webksu_suctl.aarch64") {
        let data = b.data.as_ref();
        if data.len() > 1024 {
            // 仅当内容有变化时重写，避免每次开机无谓的 IO
            let cur = std::fs::read(SUCTL_DST).unwrap_or_default();
            if cur.len() != data.len() || cur[..64.min(cur.len())] != data[..64.min(data.len())] {
                if std::fs::write(SUCTL_DST, data).is_ok() {
                    let _ = Command::new("chmod").args(["755", SUCTL_DST]).status();
                    info!("[webksu] webksu_suctl deployed ({} bytes)", data.len());
                }
            }
            return;
        }
    }
    warn!("[webksu] embedded webksu_suctl missing/placeholder — keep existing file");
}

/* 部署访问令牌（256bit 随机 hex，600 权限）：
 * 同一个值同时用于 HTTP 鉴权与 suctl 写操作（WKSU_TOKEN）。
 * 其它 root 进程直接调 suctl 没有令牌/没有祖先链，无法改写授权名单 */
const TOKEN_FILE: &str = "/data/adb/webksu/token";

fn random_token() -> String {
    // 首选内核 CSPRNG
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let mut buf = [0u8; 32];
        if f.read_exact(&mut buf).is_ok() {
            let mut s = String::with_capacity(64);
            for b in buf {
                s.push_str(&format!("{b:02x}"));
            }
            return s;
        }
    }
    // 退路：时间/pid 播种的 xorshift64*
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15)
        ^ (std::process::id() as u64) << 32;
    let mut rand_byte = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed.wrapping_mul(0x2545F4914F6CDD1D) >> 24) as u8
    };
    let mut tok = String::with_capacity(64);
    for _ in 0..32 {
        let b = rand_byte();
        tok.push(HEX[(b >> 4) as usize & 0xf] as char);
        tok.push(HEX[b as usize & 0xf] as char);
    }
    tok
}

fn deploy_token() {
    let cur = std::fs::read_to_string(TOKEN_FILE).unwrap_or_default();
    if cur.trim().len() >= 64 {
        return; // 已存在，保持稳定
    }
    let tok = format!("{}\n", random_token());
    if std::fs::write(TOKEN_FILE, &tok).is_ok() {
        let _ = Command::new("chmod").args(["600", TOKEN_FILE]).status();
        let _ = Command::new("chown").args(["0:0", TOKEN_FILE]).status();
        info!("[webksu] access token deployed");
    }
}

/* 把令牌写进系统剪贴板：root 守护进程自己没有剪贴板权限，
 * 交给 WebKSU 管理器的无界面 Activity 完成；管理器未安装或版本过旧时静默失败。 */
fn copy_token_to_clipboard(token: &str) {
    if token.is_empty() {
        return;
    }
    let copied = Command::new("/system/bin/am")
        .args([
            "start",
            "-n",
            "com.shichumo.webksu/com.resukisu.resukisu.ui.CopyTokenActivity",
            "--es",
            "text",
            token,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if copied {
        info!("[webksu] token copied to clipboard");
    } else {
        warn!("[webksu] copy token failed (WebKSU manager missing or too old?)");
    }
}

fn read_conf() -> Conf {
    // WEB_ENABLED 缺省为开：独立版就是冲着网页管理器编译的；写 WEB_ENABLED=0 可退回普通 ksud
    let mut c = Conf {
        port: 18080,
        bind: "127.0.0.1".to_string(),
        token: String::new(),
        web_enabled: true,
        copy_token: true,
    };
    if let Ok(text) = std::fs::read_to_string(CONF_PATH) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let v = v.trim().trim_matches('"').trim_matches('\'');
                match k.trim() {
                    "PORT" => {
                        if let Ok(p) = v.parse() {
                            c.port = p;
                        }
                    }
                    "BIND" => {
                        if !v.is_empty() {
                            c.bind = v.to_string();
                        }
                    }
                    "TOKEN" => c.token = v.to_string(),
                    "WEB_ENABLED" => c.web_enabled = v == "1" || v.eq_ignore_ascii_case("true"),
                    "COPY_TOKEN" => c.copy_token = v != "0" && !v.eq_ignore_ascii_case("false"),
                    _ => {}
                }
            }
        }
    }
    c
}

fn serve() -> Result<()> {
    let conf = read_conf();
    let _ = std::fs::create_dir_all("/data/adb/webksu");
    let _ = std::fs::create_dir_all("/data/adb/webksu/webroot"); // 外部网页目录：网页在线更新的写入目标
    deploy_suctl();
    deploy_token();
    // 当前生效令牌：conf TOKEN 优先，否则用 suctl 令牌文件；每次请求都会重新读，
    // 所以改 webksu.conf 后无需重启服务即可生效
    let token = current_http_token();
    if token.is_empty() {
        bail!("http token unavailable (deploy_token failed)");
    }
    let _ = std::fs::write(PID_FILE, std::process::id().to_string());
    let addr = if conf.bind.contains(':') {
        format!("[{}]:{}", conf.bind, conf.port)
    } else {
        format!("{}:{}", conf.bind, conf.port)
    };
    let listener = TcpListener::bind(&addr).with_context(|| format!("bind {addr} failed"))?;
    sync_entry_file(&token);
    // 启动即把令牌放进剪贴板，省去手动查 entry.txt；COPY_TOKEN=0 可关掉
    if conf.copy_token {
        copy_token_to_clipboard(&token);
    }
    info!("[webksu] embedded web ui on http://{addr} (entry with token: {ENTRY_FILE})");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                std::thread::spawn(move || {
                    if let Err(e) = handle(s) {
                        warn!("[webksu] connection error: {e:#}");
                    }
                });
            }
            Err(e) => warn!("[webksu] accept error: {e}"),
        }
    }
    Ok(())
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/* 当前生效的 HTTP 令牌：conf TOKEN 优先，其次 suctl 令牌文件。
 * 每个请求都会重新读，改 webksu.conf 的 TOKEN= 无需重启服务。 */
fn current_http_token() -> String {
    let c = read_conf();
    let t = c.token.trim();
    if !t.is_empty() {
        return t.to_string();
    }
    std::fs::read_to_string(TOKEN_FILE)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/* 令牌变化时同步 entry.txt，保证剪贴板里/看到的入口地址与当前令牌一致 */
fn sync_entry_file(token: &str) {
    if token.is_empty() {
        return;
    }
    let c = read_conf();
    let host = if c.bind.contains(':') {
        format!("[{}]", c.bind)
    } else {
        c.bind.clone()
    };
    let want = format!("http://{host}:{}/?t={token}\n", c.port);
    let cur = std::fs::read_to_string(ENTRY_FILE).unwrap_or_default();
    if cur != want {
        if std::fs::write(ENTRY_FILE, want).is_ok() {
            let _ = Command::new("chmod").args(["600", ENTRY_FILE]).status();
            let _ = Command::new("chown").args(["0:0", ENTRY_FILE]).status();
            info!("[webksu] entry.txt updated (token changed)");
        }
    }
}

fn handle(mut stream: TcpStream) -> Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));

    // 读取请求头
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(p) = find_sub(&buf, b"\r\n\r\n") {
            break p;
        }
        if buf.len() > 64 * 1024 {
            bail!("request header too large");
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            bail!("connection closed");
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut it = req_line.split_whitespace();
    let method = it.next().unwrap_or("").to_string();
    let target = it.next().unwrap_or("").to_string();

    let mut content_length = 0usize;
    let mut header_token = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            } else if k.eq_ignore_ascii_case("x-token") {
                header_token = v.trim().to_string();
            }
        }
    }

    // 读取请求体
    if content_length > MAX_BODY {
        bail!("request body too large");
    }
    let mut body: Vec<u8> = buf[head_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target.as_str(), ""),
    };

    if method == "OPTIONS" {
        return respond(&mut stream, "204 No Content", "text/plain", &[], &[]);
    }

    // 只有 /cgi-bin/api 需要令牌；页面、shim、/mod/ 代理必须免令牌，
    // 否则浏览器打开模块 WebUI 及其子资源会 403（令牌只保护 root API）
    let token = current_http_token();
    sync_entry_file(&token);

    if path == "/" || path == "/index.html" {
        // 外部覆盖优先：更新网页只需替换文件，浏览器刷新即生效
        if let Ok(page) = std::fs::read(EXT_INDEX) {
            if !page.is_empty() {
                return respond(&mut stream, "200 OK", "text/html; charset=utf-8", &[], &page);
            }
        }
        return match WebAssets::get("index.html") {
            Some(page) => respond(&mut stream, "200 OK", "text/html; charset=utf-8", &[], page.data.as_ref()),
            None => respond(&mut stream, "404 Not Found", "text/plain", &[], b"no embedded web ui"),
        };
    }

    if path == "/cgi-bin/api" {
        let q = query_param(query, "t").unwrap_or_default();
        if token.is_empty() || (q != token && header_token != token) {
            return respond(&mut stream, "403 Forbidden", "text/plain", &[], b"forbidden: token mismatch");
        }
        return api(&mut stream, query, &body);
    }

    /* 其它模块的 WebUI 代理：/mod/<模块id>/[子路径] —— 读模块 webroot，
       HTML 自动注入 ksu 桥垫片，让模块网页在浏览器里照常调用 ksu.exec 等 */
    if let Some(rest) = path.strip_prefix("/mod/") {
        return serve_module_file(&mut stream, rest);
    }
    if path == "/__ksu_shim.js" {
        return respond(&mut stream, "200 OK", "application/javascript; charset=utf-8", &[], KSU_SHIM.as_bytes());
    }

    respond(&mut stream, "404 Not Found", "text/plain", &[], b"not found")
}

fn mime_of(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "txt" | "md" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn serve_module_file(stream: &mut TcpStream, url_path: &str) -> Result<()> {
    let mut it = url_path.splitn(2, '/');
    let module_id = it.next().unwrap_or("");
    let rel = it.next().unwrap_or("");
    if module_id.is_empty()
        || !module_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        || module_id.contains("..")
    {
        return respond(stream, "400 Bad Request", "text/plain", &[], b"bad module id");
    }
    let rel = if rel.is_empty() { "index.html" } else { rel };
    if rel.contains("..") || rel.starts_with('/') {
        return respond(stream, "400 Bad Request", "text/plain", &[], b"bad path");
    }
    let full = format!("/data/adb/modules/{module_id}/webroot/{rel}");
    let data = match std::fs::read(&full) {
        Ok(d) => d,
        Err(_) => return respond(stream, "404 Not Found", "text/plain", &[], b"module file not found"),
    };
    let ctype = mime_of(rel);
    if ctype.starts_with("text/html") {
        let mut page = String::from_utf8_lossy(&data).into_owned();
        if !page.contains("webksu-shim") {
            let tag = "<script src=/__ksu_shim.js id=webksu-shim></script>";
            match page.find("<head") {
                Some(i) => {
                    let j = page[i..].find('>').map(|k| i + k + 1).unwrap_or(i + 5);
                    page.insert_str(j, tag);
                }
                None => page.insert_str(0, tag),
            }
        }
        return respond(stream, "200 OK", ctype, &[], page.as_bytes());
    }
    respond(stream, "200 OK", ctype, &[], &data)
}

/* 注入到模块 WebUI 的 ksu 桥垫片：把 ksu.exec/toast/moduleInfo 映射到本服务器 API */
const KSU_SHIM: &str = r#"(function () {
  if (window.ksu) return;
  function b64e(s) { return btoa(unescape(encodeURIComponent(s))); }
  function ub64d(s) {
    try { return decodeURIComponent(escape(atob(String(s || '').replace(/-/g, '+').replace(/_/g, '/')))); }
    catch (e) { return ''; }
  }
  var TOKEN = '';
  try {
    var tm = location.search.match(/[?&]t=([0-9a-fA-F]{64})/);
    if (tm) localStorage.setItem('webksu-token', tm[1].toLowerCase());
    TOKEN = localStorage.getItem('webksu-token') || '';
  } catch (e) {}
  function tokenNow() {
    try { return localStorage.getItem('webksu-token') || TOKEN; } catch (e) { return TOKEN; }
  }
  function apiExec(cmd) {
    return fetch('/cgi-bin/api?op=exec', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', 'X-Token': tokenNow() },
      body: b64e(cmd)
    }).then(function (r) {
      return r.text().then(function (t) {
        return { errno: Number(r.headers.get('X-E') || '0'), stdout: t, stderr: ub64d(r.headers.get('X-S')) };
      });
    });
  }
  var MOD_ID = '';
  try { MOD_ID = location.pathname.split('/')[2] || ''; } catch (e) {}
  window.ksu = {
    exec: function (cmd, options, callback) {
      var cb = (typeof callback === 'string') ? window[callback] : callback;
      apiExec(cmd).then(function (r) { if (cb) cb(r.errno, r.stdout, r.stderr); })
        .catch(function (e) { if (cb) cb(1, '', String(e)); });
    },
    toast: function (msg) { try { console.log('[toast]', msg); } catch (e) {} },
    fullScreen: function () {},
    moduleInfo: function () {
      try {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/cgi-bin/api?op=exec', false);
        xhr.setRequestHeader('Content-Type', 'text/plain');
        xhr.setRequestHeader('X-Token', TOKEN);
        xhr.send(b64e('cat /data/adb/modules/' + MOD_ID + '/module.prop 2>/dev/null'));
        var info = { mid: MOD_ID };
        (xhr.responseText || '').split('\n').forEach(function (l) {
          var i = l.indexOf('=');
          if (i > 0) info[l.slice(0, i).trim()] = l.slice(i + 1).trim();
        });
        return JSON.stringify(info);
      } catch (e) { return '{}'; }
    }
  };
})();
"#;

fn api(stream: &mut TcpStream, query: &str, body: &[u8]) -> Result<()> {
    match query_param(query, "op").as_deref() {
        Some("ping") => {
            let conf = read_conf();
            let out = format!("pong webksu 1.0 bind={} port={}", conf.bind, conf.port);
            respond(stream, "200 OK", "text/plain", &[], out.as_bytes())
        }
        Some("exec") => {
            let cmd = String::from_utf8(b64_decode(body).context("bad base64 body")?)
                .context("command is not utf8")?;
            // 通用命令一律不注入 WKSU_TOKEN：suctl 的写操作只能走下面的 op=suctl
            let out = Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .env("PATH", "/data/adb/ksu/bin:/system/bin:/system/xbin:/sbin")
                .current_dir("/")
                .output()
                .with_context(|| format!("exec failed: {cmd}"))?;
            let errno = out.status.code().unwrap_or(1).to_string();
            let stderr_b64 = b64url_encode(&out.stderr);
            respond(
                stream,
                "200 OK",
                "application/octet-stream",
                &[("X-E", errno.as_str()), ("X-S", stderr_b64.as_str())],
                &out.stdout,
            )
        }
        Some("suctl") => {
            let action = query_param(query, "a").unwrap_or_default().to_ascii_lowercase();
            let pkg = query_param(query, "pkg").unwrap_or_default();
            let uid_raw = query_param(query, "uid").unwrap_or_default();
            let need_pkg = matches!(action.as_str(), "grant" | "revoke");
            let need_uid = matches!(action.as_str(), "grant" | "revoke" | "granted" | "get");
            if !matches!(action.as_str(), "info" | "list" | "granted" | "grant" | "revoke" | "get") {
                return respond(stream, "400 Bad Request", "text/plain", &[], b"bad suctl action");
            }
            if need_pkg && !valid_pkg(&pkg) {
                return respond(stream, "400 Bad Request", "text/plain", &[], b"bad package name");
            }
            let uid = if need_uid {
                match uid_raw.trim().parse::<u32>() {
                    Ok(v) if v < 1_000_000_000 => v,
                    _ => return respond(stream, "400 Bad Request", "text/plain", &[], b"bad uid"),
                }
            } else {
                0
            };
            let token = std::fs::read_to_string(TOKEN_FILE).unwrap_or_default();
            let token = token.trim();
            if token.is_empty() {
                return respond(stream, "500 Internal Server Error", "text/plain", &[], b"suctl token missing");
            }
            let mut c = Command::new(SUCTL_DST);
            c.arg(&action)
                .env("PATH", "/data/adb/ksu/bin:/system/bin:/system/xbin:/sbin")
                .env("WKSU_TOKEN", token)
                .current_dir("/");
            if need_pkg {
                c.arg(&pkg);
            }
            if need_uid {
                c.arg(uid.to_string());
            }
            let out = c.output().with_context(|| format!("suctl {action} failed"))?;
            let errno = out.status.code().unwrap_or(1).to_string();
            let stderr_b64 = b64url_encode(&out.stderr);
            respond(
                stream,
                "200 OK",
                "application/octet-stream",
                &[("X-E", errno.as_str()), ("X-S", stderr_b64.as_str())],
                &out.stdout,
            )
        }
        Some("write") => {
            let raw_path = query_param(query, "p").context("missing p param")?;
            let target = String::from_utf8(b64_decode(raw_path.as_bytes()).context("bad p base64")?)
                .context("path is not utf8")?;
            if !target.starts_with("/data/") {
                return respond(stream, "400 Bad Request", "text/plain", &[], b"refused: path must be under /data");
            }
            let data = b64_decode(body).context("bad base64 body")?;
            // 自动创建父目录（如网页在线更新的 /data/adb/webksu/webroot/），并把打开失败转为 HTTP 500 而不是掐断连接
            if let Some(parent) = std::path::Path::new(&target).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mode = query_param(query, "m").unwrap_or_default();
            let f = if mode == "a" {
                std::fs::OpenOptions::new().create(true).append(true).open(&target)
            } else {
                std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&target)
            };
            let mut f = match f {
                Ok(f) => f,
                Err(e) => {
                    let msg = format!("open {target} failed: {e}");
                    return respond(stream, "500 Internal Server Error", "text/plain", &[], msg.as_bytes());
                }
            };
            f.write_all(&data).context("write body")?;
            let msg = format!("ok {}", data.len());
            respond(stream, "200 OK", "text/plain", &[], msg.as_bytes())
        }
        _ => respond(stream, "400 Bad Request", "text/plain", &[], b"unknown op"),
    }
}

/* 包名合法性：Android 包名只含字母数字 . _ -，且不能以符号/连字符开头、不能含 .. */
fn valid_pkg(pkg: &str) -> bool {
    if pkg.is_empty() || pkg.len() > 255 || pkg.contains("..") {
        return false;
    }
    let bytes = pkg.as_bytes();
    let first = bytes[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return false;
    }
    bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'_' || *b == b'-')
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key {
                return Some(v.to_string());
            }
        } else if kv == key {
            return Some(String::new());
        }
    }
    None
}

fn respond(stream: &mut TcpStream, status: &str, ctype: &str, extra: &[(&str, &str)], body: &[u8]) -> Result<()> {
    let mut head = format!("HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n{COMMON_HEADERS}");
    for (k, v) in extra {
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    head.push_str("Content-Length: ");
    head.push_str(&body.len().to_string());
    head.push_str("\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

/* base64：解码同时接受标准和 URL-safe 字母表；编码输出 URL-safe（用于 X-S 头） */
fn b64_decode(input: &[u8]) -> Result<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in input {
        if c.is_ascii_whitespace() || c == b'=' {
            continue;
        }
        let v = val(c).context("invalid base64 char")?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

fn b64url_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(T[(acc >> bits) as usize & 0x3f] as char);
        }
    }
    if bits > 0 {
        out.push(T[((acc << (6 - bits)) & 0x3f) as usize] as char);
    }
    out
}
