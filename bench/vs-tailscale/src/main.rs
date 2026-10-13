//! vsts: net.mesh vs Tailscale on the same machines in the same minute.
//! std only, one file, so any host builds it with plain `rustc -O main.rs -o vsts`.
//!
//!   vsts serve --bind ADDR[,ADDR] --port P [--max-secs 1800]
//!       TCP echo/sink/source on each ADDR (a mesh or tailnet address, never 0.0.0.0). Prints "ready".
//!       Exits on stdin EOF (the ssh that started it went away) or after --max-secs, whichever first.
//!   vsts probe --label L --target ADDR --port P [--n 50] [--bytes 2000000] [--cap-secs 60] [--what connect,down,up]
//!       one JSON line per metric: connect (fresh TCP connect + first byte, n tries, 3 s each),
//!       down (server->client), up (client->server), each capped at --cap-secs.
//!   vsts ping --label L --target ADDR [--n 100] [--interval 0.2]
//!       runs the system ping, parses every reply, one JSON line: p50/p99/loss.
//!   vsts probe-ssh --label L --host SSH_ALIAS --hostname ADDR --dir down|up [--bytes N] [--cap-secs 60]
//!       throughput through one ssh session pinned to ADDR, for an end that cannot listen (see sshd plan mode);
//!       the far end runs `vsts source --bytes N` / `vsts sink --cap-secs S`.
//!   vsts table --in FILE [--run RUN_ID]
//!       the markdown table for BENCHMARKS.md from the JSON lines (last run in FILE by default).
//!   vsts run --plan PLAN [--out FILE] [--rounds 1]
//!       the orchestrator: for each pair in PLAN, starts `serve` on the server end over ssh, then for each
//!       metric runs the mesh and Tailscale probe back to back (which goes first alternates per metric), appending
//!       every JSON line to --out with a timestamp, the pair and the transport.
//!
//! PLAN lines: `name client_ssh server_ssh mesh_server_addr|- ts_server_addr|- client_vsts server_vsts`
//! where *_ssh is `local` for this machine.
//! Wire protocol: client sends op u8 + n u64 BE. 'e': 1 byte back. 'd': n bytes back. 'u': client sends n bytes,
//! server answers the count u64 at EOF. 'r': state of the last upload (bytes u64, micros since its first byte u64).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter().position(|x| x == k).and_then(|i| a.get(i + 1).cloned())
}
fn argn(a: &[String], k: &str, d: f64) -> f64 {
    arg(a, k).map(|s| s.parse().unwrap_or(d)).unwrap_or(d)
}
fn die(m: &str) -> ! {
    eprintln!("vsts: {m}");
    std::process::exit(2)
}
fn now_iso() -> String {
    let s = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let (secs, ms) = (s.as_secs(), s.subsec_millis());
    let (d, r) = (secs / 86400, secs % 86400);
    let (y, m, dd) = civil(d as i64);
    format!("{y:04}-{m:02}-{dd:02}T{:02}:{:02}:{:02}.{ms:03}Z", r / 3600, r % 3600 / 60, r % 60)
}
fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}
fn pct(v: &[f64], p: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Some(s[((p / 100.0) * (s.len() - 1) as f64).round() as usize])
}
fn js(o: Option<f64>) -> String {
    o.map(|x| format!("{x:.2}")).unwrap_or_else(|| "null".into())
}
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---------------------------------------------------------------- serve
fn serve(a: &[String]) {
    let port = arg(a, "--port").unwrap_or_else(|| die("--port"));
    let max = argn(a, "--max-secs", 1800.0).min(3600.0);
    let binds = arg(a, "--bind").unwrap_or_else(|| die("--bind"));
    let last_up = Arc::new((AtomicU64::new(0), AtomicU64::new(0))); // bytes, start micros since t0
    let t0 = Instant::now();
    let live = Arc::new(AtomicUsize::new(0));
    for b in binds.split(',') {
        if b.starts_with("0.0.0.0") || b == "::" {
            die("refusing to bind a wildcard address");
        }
        let l = TcpListener::bind(format!("{b}:{port}")).unwrap_or_else(|e| die(&format!("bind {b}:{port}: {e}")));
        let (lu, live) = (last_up.clone(), live.clone());
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                if live.load(Ordering::SeqCst) >= 8 {
                    continue; // drop: at most 8 connections at a time
                }
                live.fetch_add(1, Ordering::SeqCst);
                let (lu, live) = (lu.clone(), live.clone());
                std::thread::spawn(move || {
                    let _ = handle(c, &lu, t0);
                    live.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
    }
    println!("ready");
    std::io::stdout().flush().ok();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs_f64(max));
        std::process::exit(0)
    });
    let mut buf = [0u8; 64];
    while let Ok(n) = std::io::stdin().read(&mut buf) {
        if n == 0 {
            break;
        }
    }
}

fn handle(mut c: TcpStream, lu: &(AtomicU64, AtomicU64), t0: Instant) -> std::io::Result<()> {
    c.set_nodelay(true)?;
    c.set_read_timeout(Some(Duration::from_secs(120)))?;
    c.set_write_timeout(Some(Duration::from_secs(120)))?;
    let mut h = [0u8; 9];
    c.read_exact(&mut h)?;
    let n = u64::from_be_bytes(h[1..9].try_into().unwrap()).min(64 << 20);
    match h[0] {
        b'e' => c.write_all(b"k")?,
        b'd' => {
            let chunk = vec![0x5au8; 65536];
            let mut left = n;
            while left > 0 {
                let k = left.min(chunk.len() as u64) as usize;
                c.write_all(&chunk[..k])?;
                left -= k as u64;
            }
        }
        b'u' => {
            lu.0.store(0, Ordering::SeqCst);
            let mut buf = vec![0u8; 65536];
            let mut got = 0u64;
            loop {
                let k = c.read(&mut buf)?;
                if k == 0 {
                    break;
                }
                if got == 0 {
                    lu.1.store(t0.elapsed().as_micros() as u64, Ordering::SeqCst);
                }
                got += k as u64;
                lu.0.store(got, Ordering::SeqCst);
            }
            c.write_all(&got.to_be_bytes())?;
        }
        b'r' => {
            let b = lu.0.load(Ordering::SeqCst);
            let us = (t0.elapsed().as_micros() as u64).saturating_sub(lu.1.load(Ordering::SeqCst));
            c.write_all(&b.to_be_bytes())?;
            c.write_all(&us.to_be_bytes())?;
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------- probe
fn open(addr: &SocketAddr, op: u8, n: u64, to: Duration) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect_timeout(addr, to)?;
    s.set_nodelay(true)?;
    let mut h = [0u8; 9];
    h[0] = op;
    h[1..].copy_from_slice(&n.to_be_bytes());
    s.write_all(&h)?;
    Ok(s)
}

fn probe(a: &[String]) {
    let label = arg(a, "--label").unwrap_or_default();
    let target = arg(a, "--target").unwrap_or_else(|| die("--target"));
    let port = arg(a, "--port").unwrap_or_else(|| die("--port"));
    let addr = format!("{target}:{port}").to_socket_addrs().ok().and_then(|mut x| x.next()).unwrap_or_else(|| die("addr"));
    let n = argn(a, "--n", 50.0).min(500.0) as usize;
    let bytes = argn(a, "--bytes", 2e6).min(64e6) as u64;
    let cap = argn(a, "--cap-secs", 60.0).min(120.0);
    let what = arg(a, "--what").unwrap_or_else(|| "connect,down,up".into());
    for w in what.split(',') {
        let line = match w {
            "connect" => p_connect(&addr, n),
            "down" => p_down(&addr, bytes, cap),
            "up" => p_up(&addr, bytes, cap),
            _ => continue,
        };
        println!("{{\"label\":\"{}\",\"metric\":\"{w}\",{line}}}", esc(&label));
        std::io::stdout().flush().ok();
    }
}

fn p_connect(addr: &SocketAddr, n: usize) -> String {
    let (mut conn, mut first, mut fails, mut errs) = (vec![], vec![], 0, String::new());
    for i in 0..n {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(100));
        }
        let t = Instant::now();
        let r = (|| -> std::io::Result<(f64, f64)> {
            let mut s = TcpStream::connect_timeout(addr, Duration::from_secs(3))?;
            let c = t.elapsed().as_secs_f64() * 1e3;
            s.set_nodelay(true)?;
            s.set_read_timeout(Some(Duration::from_secs(3)))?;
            s.write_all(&[b'e', 0, 0, 0, 0, 0, 0, 0, 0])?;
            let mut b = [0u8; 1];
            s.read_exact(&mut b)?;
            Ok((c, t.elapsed().as_secs_f64() * 1e3))
        })();
        match r {
            Ok((c, f)) => {
                conn.push(c);
                first.push(f);
            }
            Err(e) => {
                fails += 1;
                if errs.is_empty() {
                    errs = e.to_string();
                }
            }
        }
    }
    format!(
        "\"n\":{n},\"ok\":{},\"fail\":{fails},\"connect_p50_ms\":{},\"connect_p99_ms\":{},\"first_byte_p50_ms\":{},\"first_byte_p99_ms\":{},\"first_byte_max_ms\":{},\"err\":\"{}\"",
        conn.len(),
        js(pct(&conn, 50.0)),
        js(pct(&conn, 99.0)),
        js(pct(&first, 50.0)),
        js(pct(&first, 99.0)),
        js(pct(&first, 100.0)),
        esc(&errs)
    )
}

fn rate(b: u64, s: f64) -> String {
    if s > 0.0 { format!("{:.1}", b as f64 / s / 1e3) } else { "null".into() }
}

fn p_down(addr: &SocketAddr, n: u64, cap: f64) -> String {
    let t = Instant::now();
    let dl = t + Duration::from_secs_f64(cap);
    let mut got = 0u64;
    let mut err = String::new();
    match open(addr, b'd', n, Duration::from_secs(5)) {
        Ok(mut s) => {
            let mut buf = vec![0u8; 65536];
            while got < n {
                let left = dl.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                s.set_read_timeout(Some(left)).ok();
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(k) => got += k as u64,
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock && e.kind() != std::io::ErrorKind::TimedOut {
                            err = e.to_string();
                        }
                        break;
                    }
                }
            }
        }
        Err(e) => err = e.to_string(),
    }
    let secs = t.elapsed().as_secs_f64();
    format!(
        "\"bytes_asked\":{n},\"bytes\":{got},\"secs\":{secs:.2},\"complete\":{},\"kB_per_s\":{},\"err\":\"{}\"",
        got >= n,
        rate(got, secs),
        esc(&err)
    )
}

fn p_up(addr: &SocketAddr, n: u64, cap: f64) -> String {
    let t = Instant::now();
    let dl = t + Duration::from_secs_f64(cap);
    let mut err = String::new();
    let mut acked: Option<u64> = None;
    let mut s = match open(addr, b'u', n, Duration::from_secs(5)) {
        Ok(s) => Some(s),
        Err(e) => {
            err = e.to_string();
            None
        }
    };
    if let Some(s) = s.as_mut() {
        let chunk = vec![0xa5u8; 16384];
        let mut sent = 0u64;
        let mut timed_out = false;
        while sent < n {
            let left = dl.saturating_duration_since(Instant::now());
            if left.is_zero() {
                timed_out = true;
                break;
            }
            s.set_write_timeout(Some(left)).ok();
            let k = (n - sent).min(chunk.len() as u64) as usize;
            match s.write(&chunk[..k]) {
                Ok(w) => sent += w as u64,
                Err(_) => {
                    timed_out = true;
                    break;
                }
            }
        }
        if !timed_out {
            let _ = s.shutdown(Shutdown::Write);
            let left = dl.saturating_duration_since(Instant::now());
            if !left.is_zero() {
                s.set_read_timeout(Some(left)).ok();
                let mut b = [0u8; 8];
                if s.read_exact(&mut b).is_ok() {
                    acked = Some(u64::from_be_bytes(b));
                }
            }
        }
    }
    let secs = t.elapsed().as_secs_f64();
    if let Some(b) = acked {
        drop(s);
        return format!(
            "\"bytes_asked\":{n},\"bytes\":{b},\"secs\":{secs:.2},\"complete\":{},\"kB_per_s\":{},\"err\":\"\"",
            b >= n,
            rate(b, secs)
        );
    }
    // cap hit: ask the server how much arrived, then drop the upload
    let (mut b, mut us) = (0u64, 0u64);
    if let Ok(mut r) = open(addr, b'r', 0, Duration::from_secs(10)) {
        r.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut buf = [0u8; 16];
        if r.read_exact(&mut buf).is_ok() {
            b = u64::from_be_bytes(buf[..8].try_into().unwrap());
            us = u64::from_be_bytes(buf[8..].try_into().unwrap());
        } else {
            err = "cap hit; server state read failed".into();
        }
    } else if err.is_empty() {
        err = "cap hit; server state connect failed".into();
    }
    drop(s);
    let srv_secs = us as f64 / 1e6;
    format!(
        "\"bytes_asked\":{n},\"bytes\":{b},\"secs\":{secs:.2},\"server_secs\":{srv_secs:.2},\"complete\":false,\"kB_per_s\":{},\"err\":\"{}\"",
        rate(b, srv_secs.max(secs.min(srv_secs + 1.0))),
        esc(&err)
    )
}

// ---------------------------------------------------------------- ping
fn ping(a: &[String]) {
    let label = arg(a, "--label").unwrap_or_default();
    let target = arg(a, "--target").unwrap_or_else(|| die("--target"));
    let n = argn(a, "--n", 100.0).min(500.0) as usize;
    let iv = argn(a, "--interval", 0.2).max(0.2);
    let bin = if std::path::Path::new("/sbin/ping").exists() { "/sbin/ping" } else { "ping" };
    let cap = (n as f64 * iv + 15.0) as u64;
    let out = Command::new("timeout")
        .args([&cap.to_string(), bin, "-n", "-c", &n.to_string(), "-i", &iv.to_string(), &target])
        .output()
        .or_else(|_| Command::new(bin).args(["-n", "-c", &n.to_string(), "-i", &iv.to_string(), "-t", &cap.to_string(), &target]).output());
    let text = out.map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let mut rtt = vec![];
    for l in text.lines() {
        if let Some(i) = l.find("time=") {
            let v: String = l[i + 5..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
            if let Ok(x) = v.parse::<f64>() {
                rtt.push(x);
            }
        }
    }
    let loss = 100.0 * (n - rtt.len().min(n)) as f64 / n as f64;
    println!(
        "{{\"label\":\"{}\",\"metric\":\"ping\",\"n\":{n},\"replies\":{},\"loss_pct\":{loss:.1},\"rtt_p50_ms\":{},\"rtt_p99_ms\":{},\"rtt_min_ms\":{},\"rtt_max_ms\":{}}}",
        esc(&label),
        rtt.len(),
        js(pct(&rtt, 50.0)),
        js(pct(&rtt, 99.0)),
        js(pct(&rtt, 0.0)),
        js(pct(&rtt, 100.0))
    );
}

// ---------------------------------------------------------------- run (orchestrator)
fn cmd_on(host: &str, line: &str) -> Command {
    if host == "local" {
        let mut c = Command::new("sh");
        c.args(["-c", line]);
        c
    } else {
        let mut c = Command::new("ssh");
        c.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=30", "-o", "ControlPath=none", host, line]);
        c
    }
}

fn run_capture(host: &str, line: &str, cap: u64) -> Vec<String> {
    let full = format!("timeout {cap} {line}");
    // the Macs have no GNU timeout; the probe caps itself, so wrap only locally / on Linux
    let line = if host == "local" || std::env::var("VSTS_FULL_HOSTS").map(|v| v.split(',').any(|h| h == host)).unwrap_or(false) { full } else { line.to_string() };
    let mut child = match cmd_on(host, &line).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let out = child.stdout.take().unwrap();
    let t = Instant::now();
    let h = std::thread::spawn(move || BufReader::new(out).lines().map_while(Result::ok).collect::<Vec<_>>());
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        if t.elapsed().as_secs() > cap + 30 {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.wait();
    h.join().unwrap_or_default()
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_server(host: &str, vsts: &str, binds: &str, port: u16) -> Option<Server> {
    let line = format!("{vsts} serve --bind {binds} --port {port} --max-secs 1500");
    let mut c = cmd_on(host, &line).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().ok()?;
    let out = c.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut l = String::new();
        let _ = BufReader::new(out).read_line(&mut l);
        let _ = tx.send(l);
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(l) if l.trim() == "ready" => Some(Server(c)),
        _ => {
            let _ = c.kill();
            None
        }
    }
}

fn run(a: &[String]) {
    let plan = std::fs::read_to_string(arg(a, "--plan").unwrap_or_else(|| die("--plan"))).unwrap_or_else(|e| die(&e.to_string()));
    let outp = arg(a, "--out").unwrap_or_else(|| "runs.jsonl".into());
    let rounds = argn(a, "--rounds", 1.0).min(5.0) as usize;
    let bytes = argn(a, "--bytes", 2e6) as u64;
    let cap = argn(a, "--cap-secs", 60.0).min(120.0);
    let only = arg(a, "--metrics").unwrap_or_else(|| "connect,ping,down,up".into());
    let port: u16 = argn(a, "--port", 47391.0) as u16;
    let run_id = now_iso();
    let mut out = std::fs::OpenOptions::new().create(true).append(true).open(&outp).unwrap_or_else(|e| die(&e.to_string()));
    for round in 0..rounds {
        for pl in plan.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
            let f: Vec<&str> = pl.split_whitespace().collect();
            if f.len() < 7 {
                eprintln!("skip plan line: {pl}");
                continue;
            }
            let (name, cli, srv, mesh, ts, cv, sv) = (f[0], f[1], f[2], f[3], f[4], f[5], f[6]);
            let mut paths: Vec<(&str, &str)> = vec![];
            if mesh != "-" {
                paths.push(("mesh", mesh));
            }
            if ts != "-" {
                paths.push(("tailscale", ts));
            }
            let binds: Vec<&str> = paths.iter().map(|p| p.1).collect();
            eprintln!("[{}] {name}: start server on {srv} ({})", now_iso(), binds.join(","));
            let sshd = sv == "sshd";
            // fields 8/9 (optional): the client's mesh and tailnet address, for pinging from the server end
            let back: Vec<&str> = vec![f.get(7).copied().unwrap_or("-"), f.get(8).copied().unwrap_or("-")];
            let server = match if sshd { None } else { start_server(srv, sv, &binds.join(","), port) } {
                Some(s) => Some(s),
                None if sshd => None,
                None => {
                    let l = format!("{{\"ts\":\"{}\",\"run\":\"{run_id}\",\"pair\":\"{name}\",\"error\":\"server did not start on {srv}\"}}", now_iso());
                    writeln!(out, "{l}").ok();
                    continue;
                }
            };
            for (mi, metric) in only.split(',').enumerate() {
                let mut order = paths.clone();
                if (mi + round) % 2 == 1 {
                    order.reverse();
                }
                for (tr, addr) in &order {
                    let label = format!("{name}/{tr}");
                    let back_addr = if *tr == "mesh" { back[0] } else { back[1] };
                    let mut on = cli;
                    let (line, capsec) = match metric {
                        // sshd mode: the server end cannot listen (macOS stealth firewall), so its sshd is the far
                        // end: connect = TCP connect + SSH banner on :22, ping runs from the server end toward the
                        // client, throughput = bytes through `ssh -o HostName=<addr>` (same ssh cost on both paths)
                        "ping" if sshd => {
                            on = srv;
                            (format!("{sv_bin} ping --label {label} --target {back_addr} --n 100 --interval 0.2", sv_bin = f.get(9).copied().unwrap_or("~/.cache/vsts/vsts")), 40)
                        }
                        "connect" if sshd => (format!("{cv} probe --label {label} --target {addr} --port 22 --what connect --n 50"), 400),
                        "down" | "up" if sshd => (
                            format!("{cv} probe-ssh --label {label} --host {srv} --hostname {addr} --dir {metric} --bytes {bytes} --cap-secs {cap}"),
                            cap as u64 + 60,
                        ),
                        "ping" => (format!("{cv} ping --label {label} --target {addr} --n 100 --interval 0.2"), 40),
                        "connect" => (format!("{cv} probe --label {label} --target {addr} --port {port} --what connect --n 50"), 400),
                        "down" | "up" => (
                            format!("{cv} probe --label {label} --target {addr} --port {port} --what {metric} --bytes {bytes} --cap-secs {cap}"),
                            cap as u64 + 30,
                        ),
                        _ => continue,
                    };
                    let t = now_iso();
                    eprintln!("[{t}] {label} {metric}");
                    let lines = run_capture(on, &line, capsec);
                    let mut any = false;
                    for l in lines.iter().filter(|l| l.starts_with('{')) {
                        any = true;
                        let body = l.trim_start_matches('{');
                        writeln!(out, "{{\"ts\":\"{t}\",\"run\":\"{run_id}\",\"round\":{round},\"pair\":\"{name}\",\"client\":\"{cli}\",\"server\":\"{srv}\",\"transport\":\"{tr}\",{body}").ok();
                        eprintln!("    {l}");
                    }
                    if !any {
                        writeln!(out, "{{\"ts\":\"{t}\",\"run\":\"{run_id}\",\"round\":{round},\"pair\":\"{name}\",\"transport\":\"{tr}\",\"metric\":\"{metric}\",\"error\":\"no output\"}}").ok();
                    }
                    out.flush().ok();
                }
            }
            drop(server); // None in sshd mode
        }
    }
}

// ---------------------------------------------------------------- probe-ssh, source, sink
/// `vsts source --bytes N`: N bytes to stdout. `vsts sink --cap-secs S`: count stdin until EOF or S seconds after the
/// first byte, print "bytes secs" (secs from the first byte). The far end of probe-ssh, so no listener is needed there.
fn source(a: &[String]) {
    let n = argn(a, "--bytes", 2e6).min(64e6) as u64;
    let chunk = vec![0x5au8; 65536];
    let mut o = std::io::stdout().lock();
    let mut left = n;
    while left > 0 {
        let k = left.min(65536) as usize;
        if o.write_all(&chunk[..k]).is_err() {
            break;
        }
        left -= k as u64;
    }
}
fn sink(a: &[String]) {
    let cap = argn(a, "--cap-secs", 60.0).min(120.0);
    let (tx, rx) = std::sync::mpsc::channel::<u64>();
    let t0 = std::sync::Arc::new(std::sync::Mutex::new(None::<Instant>));
    let t0r = t0.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let mut i = std::io::stdin().lock();
        while let Ok(k) = i.read(&mut buf) {
            if k == 0 {
                break;
            }
            t0r.lock().unwrap().get_or_insert_with(Instant::now);
            let _ = tx.send(k as u64);
        }
    });
    let mut got = 0u64;
    let hard = Instant::now() + Duration::from_secs_f64(cap + 60.0); // login slack, then a hard stop
    loop {
        let start = *t0.lock().unwrap();
        let until = match start { Some(s) => s + Duration::from_secs_f64(cap), None => hard };
        let left = until.min(hard).saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(k) => got += k,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
            Err(_) => break, // EOF
        }
    }
    let secs = t0.lock().unwrap().map(|s| s.elapsed().as_secs_f64().min(cap)).unwrap_or(0.0);
    println!("{got} {secs:.3}");
    std::io::stdout().flush().ok();
    std::process::exit(0);
}

/// bytes through one ssh session to HOST with HostName set to the mesh or tailnet address; the far end runs
/// `vsts source` (down) or `vsts sink` (up). Times run from the first byte, so the ssh login is not counted.
fn probe_ssh(a: &[String]) {
    let label = arg(a, "--label").unwrap_or_default();
    let host = arg(a, "--host").unwrap_or_else(|| die("--host"));
    let hn = arg(a, "--hostname").unwrap_or_else(|| die("--hostname"));
    let dir = arg(a, "--dir").unwrap_or_else(|| die("--dir"));
    let far = arg(a, "--far-vsts").unwrap_or_else(|| "~/.cache/vsts/vsts".into());
    let n = argn(a, "--bytes", 2e6).min(64e6) as u64;
    let cap = argn(a, "--cap-secs", 60.0).min(120.0);
    let dl = dir == "down";
    let remote = if dl { format!("{far} source --bytes {n}") } else { format!("{far} sink --cap-secs {cap}") };
    let t = Instant::now();
    let mut c = Command::new("ssh")
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=30", "-o", "ControlPath=none", "-o", "Compression=no"])
        .args(["-o", &format!("HostName={hn}"), &host, &remote])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().unwrap_or_else(|e| die(&e.to_string()));
    let mut stdout = c.stdout.take().unwrap();
    let mut stdin = c.stdin.take();
    let hard = t + Duration::from_secs_f64(cap + 50.0);
    let (tx, rx) = std::sync::mpsc::channel::<(u64, Option<f64>, f64, String)>();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let (mut got, mut first, mut last, mut txt) = (0u64, None, 0.0, Vec::new());
        while let Ok(k) = stdout.read(&mut buf) {
            if k == 0 {
                break;
            }
            let now = t.elapsed().as_secs_f64();
            first.get_or_insert(now);
            got += k as u64;
            last = now;
            if !dl {
                txt.extend_from_slice(&buf[..k]);
            }
            if dl && now > first.unwrap() + cap {
                break;
            }
        }
        let _ = tx.send((got, first, last, String::from_utf8_lossy(&txt).into_owned()));
    });
    if !dl {
        let chunk = vec![0xa5u8; 16384];
        let mut sent = 0u64;
        if let Some(w) = stdin.as_mut() {
            // write until done, the far end stops reading (cap), or the hard stop
            while sent < n && Instant::now() < hard {
                let k = (n - sent).min(16384);
                if w.write_all(&chunk[..k as usize]).is_err() {
                    break;
                }
                sent += k;
            }
        }
    }
    drop(stdin);
    let res = rx.recv_timeout(hard.saturating_duration_since(Instant::now()) + Duration::from_secs(5));
    let _ = c.kill();
    let _ = c.wait();
    let (bytes, secs, err) = match res {
        Ok((g, Some(f), last, _)) if dl => (g, last - f, String::new()),
        Ok((_, _, _, txt)) if !dl => {
            let mut it = txt.split_whitespace();
            let b = it.next().and_then(|x| x.parse().ok()).unwrap_or(0u64);
            let s = it.next().and_then(|x| x.parse().ok()).unwrap_or(0.0f64);
            (b, s, if txt.trim().is_empty() { "far end printed nothing".into() } else { String::new() })
        }
        Ok(_) => (0, 0.0, "no bytes".into()),
        Err(_) => (0, 0.0, "hard stop before the far end answered".into()),
    };
    println!(
        "{{\"label\":\"{}\",\"metric\":\"{dir}\",\"via\":\"ssh\",\"bytes_asked\":{n},\"bytes\":{bytes},\"secs\":{secs:.2},\"complete\":{},\"kB_per_s\":{},\"err\":\"{}\"}}",
        esc(&label),
        bytes >= n,
        rate(bytes, secs),
        esc(&err)
    );
}

// ---------------------------------------------------------------- table
/// value of a top-level key in one of our flat JSON lines (no nesting, no escaped quotes in values we read)
fn get<'a>(l: &'a str, k: &str) -> Option<&'a str> {
    let pat = format!("\"{k}\":");
    let i = l.find(&pat)? + pat.len();
    let r = &l[i..];
    if let Some(r) = r.strip_prefix('"') {
        r.find('"').map(|j| &r[..j])
    } else {
        let j = r.find([',', '}']).unwrap_or(r.len());
        Some(&r[..j])
    }
}

fn table(a: &[String]) {
    let text = std::fs::read_to_string(arg(a, "--in").unwrap_or_else(|| die("--in"))).unwrap_or_else(|e| die(&e.to_string()));
    let lines: Vec<&str> = text.lines().collect();
    let run = arg(a, "--run").or_else(|| lines.last().and_then(|l| get(l, "run")).map(String::from)).unwrap_or_default();
    let rows: Vec<&str> = lines.into_iter().filter(|l| get(l, "run") == Some(run.as_str())).collect();
    let mut pairs: Vec<&str> = vec![];
    for r in &rows {
        if let Some(p) = get(r, "pair") {
            if !pairs.contains(&p) {
                pairs.push(p);
            }
        }
    }
    let cell = |pair: &str, tr: &str, m: &str| -> String {
        let r = match rows.iter().find(|r| get(r, "pair") == Some(pair) && get(r, "transport") == Some(tr) && get(r, "metric") == Some(m)) {
            Some(r) => *r,
            None => return "not run".into(),
        };
        if let Some(e) = get(r, "error") {
            return format!("error: {e}");
        }
        let v = |k: &str| get(r, k).unwrap_or("null").to_string();
        match m {
            "connect" if v("ok") == "0" => format!("0/{} ok: {}", v("n"), v("err")),
            "connect" => format!("{} / {} ms; first byte {} / {} ms ({}/{} ok)", v("connect_p50_ms"), v("connect_p99_ms"), v("first_byte_p50_ms"), v("first_byte_p99_ms"), v("ok"), v("n")),
            "ping" => {
                if v("replies") == "0" { format!("no replies ({}% loss)", v("loss_pct")) } else { format!("{} / {} ms, {}% loss", v("rtt_p50_ms"), v("rtt_p99_ms"), v("loss_pct")) }
            }
            _ if v("bytes") == "0" => format!("failed: {}", v("err")),
            _ => {
                let kb = v("kB_per_s");
                if v("complete") == "true" { format!("{kb} kB/s ({} MB in {} s)", v("bytes").parse::<f64>().unwrap_or(0.0) / 1e6, v("secs")) } else { format!("{kb} kB/s ({} kB in cap, incomplete)", v("bytes").parse::<f64>().unwrap_or(0.0) / 1e3) }
            }
        }
    };
    println!("Run {run}\n");
    println!("| pair (client, server) | metric | net.mesh | Tailscale |\n|---|---|---|---|");
    for p in pairs {
        let any = rows.iter().find(|r| get(r, "pair") == Some(p) && get(r, "client").is_some());
        let (c, sv) = any.map(|r| (get(r, "client").unwrap_or("?"), get(r, "server").unwrap_or("?"))).unwrap_or(("?", "?"));
        let (c, sv) = (if c == "local" { "local" } else { c }, if sv == "local" { "local" } else { sv });
        let ping = if rows.iter().any(|r| get(r, "pair") == Some(p) && get(r, "metric") == Some("ping") && get(r, "client") == Some(sv)) { format!("ping RTT {sv} -> {c}") } else { "ping RTT".into() };
        for (m, name) in [("connect", "TCP connect p50 / p99".to_string()), ("ping", format!("{ping} p50 / p99, loss")), ("down", format!("throughput {sv} -> {c}")), ("up", format!("throughput {c} -> {sv}"))] {
            println!("| {p} ({c}, {sv}) | {name} | {} | {} |", cell(p, "mesh", m), cell(p, "tailscale", m));
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("serve") => serve(&a),
        Some("probe") => probe(&a),
        Some("ping") => ping(&a),
        Some("run") => run(&a),
        Some("table") => table(&a),
        Some("probe-ssh") => probe_ssh(&a),
        Some("source") => source(&a),
        Some("sink") => sink(&a),
        _ => die("usage: vsts serve|probe|ping|run (see the header of bench/vs-tailscale/src/main.rs)"),
    }
}
