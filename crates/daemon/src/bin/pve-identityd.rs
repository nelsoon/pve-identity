//! pve-identityd: per-host issuer daemon (vsock, CT sockets, QGA push,
//! reconciler, HTTPS discovery).
use pveid::ctx::{Ctx, DEFAULT_HTTPS_PORT};
use pveid::discovery::{self, Tls};
use pveid::reconcile::Reconciler;
use std::sync::{Arc, RwLock};

fn members_ip(root: &std::path::Path, node: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join(".members")).ok()?).ok()?;
    v["nodelist"][node]["ip"].as_str().map(String::from)
}

fn tls_sans(ctx: &Ctx) -> Vec<String> {
    let mut v = vec![ctx.node.clone()];
    if let Some(ip) = members_ip(&ctx.paths.root, &ctx.node) {
        v.push(ip);
    }
    if let Some(iss) = ctx.issuer() {
        let host = iss.split_once("://").map(|x| x.1).unwrap_or(&iss);
        let host = host.split('/').next().unwrap_or("");
        let host = if host.starts_with('[') { host.trim_start_matches('[').split(']').next().unwrap_or("") } else { host.rsplit_once(':').map(|x| x.0).unwrap_or(host) };
        if !host.is_empty() {
            v.push(host.to_string());
        }
    }
    v.extend(ctx.settings.read().unwrap().san.clone());
    v
}

fn main() {
    let ctx = Arc::new(Ctx::new(Default::default()));
    pveid::log(format!("pve-identityd {} starting on node {}", env!("CARGO_PKG_VERSION"), ctx.node));
    let _ = std::fs::create_dir_all("/run/pve-identity/ct");

    let c = ctx.clone();
    std::thread::spawn(move || loop {
        if let Err(e) = pveid::vsock::serve(c.clone()) {
            pveid::log(format!("vsock: {e}; retrying"));
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    });

    let tls = Arc::new(Tls { cfg: RwLock::new(None) });
    let port = ctx.settings.read().unwrap().port.unwrap_or(DEFAULT_HTTPS_PORT);
    let (c, t) = (ctx.clone(), tls.clone());
    std::thread::spawn(move || loop {
        if let Err(e) = discovery::serve(c.clone(), t.clone(), port) {
            pveid::log(format!("https: {e}; retrying"));
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    });

    let rec = Reconciler::new(ctx.clone());
    let mut last_tls = 0u64;
    loop {
        rec.tick();
        let now = pve_identity_core::now();
        if now >= last_tls + 300 || tls.cfg.read().unwrap().is_none() && now >= last_tls + 15 {
            last_tls = now;
            if ctx.issuer().is_some() {
                match pveid::cert::ensure_tls(&ctx.paths, &ctx.node, &tls_sans(&ctx)).and_then(|(c, k)| discovery::load_config(&c, &k)) {
                    Ok(cfg) => *tls.cfg.write().unwrap() = Some(cfg),
                    Err(e) => pveid::log(format!("tls: {e}")),
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
