//! pve-identity: admin CLI (keygen, rotate, issue, verify, status).
use pve_identity_core::keys::{new_key, KeySet, State};
use pve_identity_core::registry::{self, Paths};
use pveid::ctx::{Channel, Ctx};

const USAGE: &str = "usage: pve-identity <command>
  init --issuer https://NAME[:PORT][/PATH] [--cluster NAME]
                        set issuer (identity.cfg) and create the first key
  rotate                publish a next key (signs after the pre-publish delay)
  status                issuer, keys, thumbprints, audiences
  issue VMID AUD        mint a token for a local guest (testing)
  verify TOKEN [AUD]    verify a token against the published keys";

fn die(m: impl std::fmt::Display) -> ! {
    eprintln!("pve-identity: {m}");
    std::process::exit(1)
}

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter()
        .position(|x| x == k)
        .and_then(|i| a.get(i + 1).cloned())
}

fn add_key(p: &Paths, state: State, cluster: &str) {
    let mut ks = KeySet::load(&p.keys()).unwrap_or_else(|e| die(e));
    let mut k = new_key(state, pve_identity_core::now()).unwrap_or_else(|e| die(e));
    k.cert = pveid::cert::key_cert(&k, cluster).unwrap_or_else(|e| die(format!("cert: {e}")));
    println!(
        "key {} ({:?}) thumbprint {}",
        k.kid,
        state,
        k.thumbprint().unwrap_or_default()
    );
    ks.keys.push(k);
    std::fs::create_dir_all(p.private()).unwrap_or_else(|e| die(e));
    ks.save(&p.keys()).unwrap_or_else(|e| die(e));
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let p = Paths::default();
    match a.first().map(String::as_str) {
        Some("init") => {
            let iss = arg(&a, "--issuer").unwrap_or_else(|| die("--issuer required"));
            if !iss.starts_with("https://") {
                die("issuer must be an https:// URL (R19)");
            }
            let mut cfg = std::fs::read_to_string(p.settings()).unwrap_or_default();
            let mut lines: Vec<String> = cfg
                .lines()
                .filter(|l| {
                    !l.starts_with("issuer:")
                        && !(l.starts_with("cluster:") && a.contains(&"--cluster".to_string()))
                })
                .map(String::from)
                .collect();
            lines.push(format!("issuer: {}", iss.trim_end_matches('/')));
            if let Some(c) = arg(&a, "--cluster") {
                lines.push(format!("cluster: {c}"));
            }
            cfg = lines.join("\n") + "\n";
            std::fs::write(p.settings(), cfg).unwrap_or_else(|e| die(e));
            let ctx = Ctx::new(p.clone());
            if KeySet::load(&p.keys())
                .map(|k| k.current().is_some())
                .unwrap_or(false)
            {
                println!("key exists, issuer updated");
            } else {
                add_key(&p, State::Current, &ctx.cluster());
            }
            for d in [p.issuers(), p.audiences()] {
                std::fs::create_dir_all(d).unwrap_or_else(|e| die(e));
            }
            println!(
                "issuer {} cluster {} (pve-identityd publishes issuers.d/pve.json)",
                iss,
                ctx.cluster()
            );
        }
        Some("rotate") => {
            let ctx = Ctx::new(p.clone());
            let ks = KeySet::load(&p.keys()).unwrap_or_else(|e| die(e));
            if ks.keys.iter().any(|k| k.state == State::Next) {
                die("a next key is already published");
            }
            add_key(&p, State::Next, &ctx.cluster());
            println!(
                "next key published; it starts signing after {} s",
                pve_identity_core::keys::PREPUBLISH_SECS
            );
        }
        Some("status") => {
            let ctx = Ctx::new(p.clone());
            let ks = ctx.keys.read().unwrap();
            println!(
                "issuer:    {}",
                ctx.issuer().unwrap_or_else(|| "(not configured)".into())
            );
            println!("cluster:   {}", ctx.cluster());
            println!("node:      {}", ctx.node);
            for k in &ks.keys {
                println!(
                    "key:       {} {:?} created {} thumbprint {}",
                    k.kid,
                    k.state,
                    k.created,
                    k.thumbprint().unwrap_or_else(|| "-".into())
                );
            }
            println!("audiences: {}", ctx.audiences().join(", "));
        }
        Some("issue") => {
            let vmid: u32 = a
                .get(1)
                .and_then(|x| x.parse().ok())
                .unwrap_or_else(|| die(USAGE));
            let aud = a.get(2).unwrap_or_else(|| die(USAGE));
            let ctx = Ctx::new(p);
            match ctx.issue(vmid, aud, Channel::Cli) {
                Ok((t, _)) => println!("{t}"),
                Err(e) => die(e),
            }
        }
        Some("verify") => {
            let tok = a.get(1).unwrap_or_else(|| die(USAGE));
            let ks = KeySet::load(&p.keys()).unwrap_or_else(|e| die(e));
            let v = pve_identity_core::jwt::verify_es256(tok, &ks.verifiers())
                .unwrap_or_else(|e| die(e));
            let now = pve_identity_core::now();
            if v["exp"].as_u64().unwrap_or(0) <= now {
                die("expired");
            }
            if let Some(aud) = a.get(2) {
                if v["aud"].as_str() != Some(aud) {
                    die("wrong audience");
                }
            }
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2)
        }
    }
    let _ = registry::valid_name;
}
