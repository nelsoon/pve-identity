//! Shared daemon context and the issuance check (spec "Issuance check").
use pve_identity_core::claims::{self, Guest, Kind};
use pve_identity_core::keys::KeySet;
use pve_identity_core::ratelimit::RateLimit;
use pve_identity_core::registry::{self, Mode, Paths, Settings};
use pve_identity_core::{jwt, pvecfg, Error, Result};
use std::sync::{Mutex, RwLock};

pub const VSOCK_PORT: u32 = 10245;
pub const DEFAULT_HTTPS_PORT: u16 = 8443;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Vsock,
    CtSocket,
    CtFiles,
    Push,
    Cli,
}
impl Channel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Channel::Vsock => "vsock",
            Channel::CtSocket => "ct-socket",
            Channel::CtFiles => "ct-files",
            Channel::Push => "qga-push",
            Channel::Cli => "cli",
        }
    }
}

pub struct Ctx {
    pub paths: Paths,
    pub node: String,
    pub settings: RwLock<Settings>,
    pub keys: RwLock<KeySet>,
    pub limit: Mutex<RateLimit>,
}

pub fn local_node() -> String {
    let mut b = [0u8; 256];
    unsafe { libc::gethostname(b.as_mut_ptr() as *mut libc::c_char, b.len()) };
    let s = String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(0)]).to_string();
    s.split('.').next().unwrap_or("").to_string()
}

impl Ctx {
    pub fn new(paths: Paths) -> Ctx {
        let settings = Settings::load(&paths);
        let keys = KeySet::load(&paths.keys()).unwrap_or_default();
        Ctx {
            node: local_node(),
            settings: RwLock::new(settings),
            keys: RwLock::new(keys),
            limit: Mutex::new(RateLimit::new(30, 20)),
            paths,
        }
    }
    pub fn reload(&self) {
        *self.settings.write().unwrap() = Settings::load(&self.paths);
        if let Ok(k) = KeySet::load(&self.paths.keys()) {
            *self.keys.write().unwrap() = k;
        }
    }
    pub fn cluster(&self) -> String {
        if let Some(c) = self.settings.read().unwrap().cluster.clone() {
            return c;
        }
        std::fs::read_to_string(self.paths.root.join("corosync.conf"))
            .ok()
            .and_then(|s| pvecfg::cluster_name(&s))
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "pve".into())
    }
    pub fn issuer(&self) -> Option<String> {
        self.settings.read().unwrap().issuer.clone()
    }
    pub fn lifetime(&self) -> u64 {
        self.settings.read().unwrap().lifetime.unwrap_or(300)
    }
    pub fn audiences(&self) -> Vec<String> {
        registry::audiences(&self.paths, &self.settings.read().unwrap())
    }
    pub fn mode(&self, vmid: u32) -> Mode {
        registry::load_modes(&self.paths).get(&vmid).copied().unwrap_or_default()
    }
    pub fn conf_path(&self, node: &str, kind: &Kind, vmid: u32) -> std::path::PathBuf {
        let dir = match kind {
            Kind::Qemu => "qemu-server",
            Kind::Lxc => "lxc",
        };
        self.paths.root.join("nodes").join(node).join(dir).join(format!("{vmid}.conf"))
    }

    /// Host-side truth for a guest that lives on this node.
    pub fn guest(&self, vmid: u32) -> Result<(Guest, pvecfg::GuestConf)> {
        let vl = pvecfg::vmlist(&self.paths.root);
        let e = vl.get(&vmid).ok_or_else(|| Error::Refused(format!("{vmid}: unknown guest")))?;
        if e.node != self.node {
            return Err(Error::Refused(format!("{vmid}: not on this node")));
        }
        let conf = pvecfg::GuestConf::parse(&std::fs::read_to_string(self.conf_path(&e.node, &e.kind, vmid))?);
        let pools = pvecfg::pools(&std::fs::read_to_string(self.paths.root.join("user.cfg")).unwrap_or_default());
        let pool = pools.get(&vmid).cloned();
        let gen = registry::load_gen(&self.paths, vmid)
            .filter(|g| Some(&g.pool) == pool.as_ref() && g.kind == e.kind.as_str())
            .map(|g| g.gen);
        let zmap = pvecfg::vnet_zones(&std::fs::read_to_string(self.paths.root.join("sdn/vnets.cfg")).unwrap_or_default());
        let mut zones: Vec<String> = conf.bridges().iter().filter_map(|b| zmap.get(b).cloned()).collect();
        zones.sort();
        zones.dedup();
        Ok((
            Guest {
                cluster: self.cluster(),
                kind: e.kind.clone(),
                vmid,
                node: self.node.clone(),
                pool,
                gen,
                zones,
                tags: conf.tags(),
            },
            conf,
        ))
    }

    /// The full issuance check after the channel identified `vmid`.
    pub fn issue(&self, vmid: u32, aud: &str, channel: Channel) -> Result<(String, u64)> {
        let r = self.issue_inner(vmid, aud, channel);
        match &r {
            Ok(_) => {}
            Err(e) => crate::log(format!("refuse vmid={vmid} aud={aud} channel={} reason=\"{e}\"", channel.as_str())),
        }
        r
    }

    fn issue_inner(&self, vmid: u32, aud: &str, channel: Channel) -> Result<(String, u64)> {
        let (g, _) = self.guest(vmid)?;
        let mode = self.mode(vmid);
        let ok = match (channel, mode) {
            (_, Mode::Off) => false,
            (Channel::Vsock, Mode::Push) => false,
            (Channel::Push, Mode::Vsock) => false,
            _ => true,
        };
        if !ok {
            return Err(Error::Refused(format!("mode {} forbids {}", mode.as_str(), channel.as_str())));
        }
        if !self.audiences().iter().any(|a| a == aud) {
            return Err(Error::Refused(format!("audience {aud} not registered")));
        }
        if matches!(channel, Channel::Vsock | Channel::CtSocket) && !self.limit.lock().unwrap().allow(vmid) {
            return Err(Error::Refused("rate limited".into()));
        }
        let iss = self.issuer().ok_or_else(|| Error::Refused("issuer not configured".into()))?;
        let ks = self.keys.read().unwrap();
        let key = ks.current().ok_or_else(|| Error::Refused("no signing key".into()))?;
        let c = claims::build(&g, &iss, aud, pve_identity_core::now(), self.lifetime())?;
        let tok = jwt::sign_es256(&key.signing_key()?, &key.kid, &c)?;
        crate::log(format!(
            "issue vmid={vmid} kind={} pool={} aud={aud} jti={} channel={} exp={}",
            g.kind.as_str(),
            c.pve.pool,
            c.jti,
            channel.as_str(),
            c.exp
        ));
        Ok((tok, c.exp))
    }
}


/// Answer one guest-facing HTTP request for an already-identified guest.
pub fn serve_guest<S: std::io::Read + std::io::Write>(ctx: &Ctx, s: &mut S, vmid: u32, ch: Channel) {
    use pve_identity_core::http::{read_request, respond, respond_json};
    let Ok(req) = read_request(s) else { return };
    let _ = match req.path.as_str() {
        "/v1/token" | "/token" => match req.param("aud") {
            Some(aud) => match ctx.issue(vmid, aud, ch) {
                Ok((t, exp)) => {
                    if req.param("format") == Some("json") {
                        respond_json(s, 200, &serde_json::json!({"token": t, "exp": exp}))
                    } else {
                        respond(s, 200, "application/jwt", t.as_bytes())
                    }
                }
                Err(Error::Refused(m)) if m == "rate limited" => respond(s, 429, "text/plain", b"rate limited\n"),
                Err(e) => respond(s, 403, "text/plain", format!("{e}\n").as_bytes()),
            },
            None => respond(s, 400, "text/plain", b"aud required\n"),
        },
        "/v1/audiences" => respond_json(s, 200, &serde_json::json!(ctx.audiences())),
        "/v1/identity" => match ctx.guest(vmid) {
            Ok((g, _)) if g.pool.is_some() => respond_json(
                s,
                200,
                &serde_json::json!({"vmid": vmid.to_string(), "kind": g.kind.as_str(), "pool": g.pool,
                    "sub": claims::subject(&g.cluster, g.pool.as_deref().unwrap_or(""), &g.kind, vmid)}),
            ),
            _ => respond(s, 403, "text/plain", b"no identity\n"),
        },
        _ => respond(s, 404, "text/plain", b"not found\n"),
    };
}
