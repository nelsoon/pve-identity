//! Public registry /etc/pve/identity (R15–R17), settings and per-guest state.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf, // normally /etc/pve
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            root: PathBuf::from("/etc/pve"),
        }
    }
}

impl Paths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Paths { root: root.into() }
    }
    pub fn registry(&self) -> PathBuf {
        self.root.join("identity")
    }
    pub fn issuers(&self) -> PathBuf {
        self.registry().join("issuers.d")
    }
    pub fn audiences(&self) -> PathBuf {
        self.registry().join("audiences.d")
    }
    pub fn pve_json(&self) -> PathBuf {
        self.issuers().join("pve.json")
    }
    pub fn guests_cfg(&self) -> PathBuf {
        self.registry().join("guests.cfg")
    }
    pub fn settings(&self) -> PathBuf {
        self.root.join("identity.cfg")
    }
    pub fn private(&self) -> PathBuf {
        self.root.join("priv/pve-identity")
    }
    pub fn keys(&self) -> PathBuf {
        self.private().join("keys.json")
    }
    pub fn gen_dir(&self) -> PathBuf {
        self.private().join("gen")
    }
    pub fn node_state(&self, node: &str) -> PathBuf {
        self.root.join("nodes").join(node).join("pve-identity.json")
    }
}

/// /etc/pve/identity.cfg: `key: value` lines.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub issuer: Option<String>,
    pub cluster: Option<String>,
    pub port: Option<u16>,
    pub lifetime: Option<u64>,
    /// Operator-added audiences (R16), comma separated.
    pub audiences: Vec<String>,
    /// Extra DNS names / IPs for the HTTPS cert.
    pub san: Vec<String>,
}

impl Settings {
    pub fn parse(s: &str) -> Settings {
        let mut o = Settings::default();
        for l in s.lines() {
            let l = l.trim();
            if l.starts_with('#') || l.is_empty() {
                continue;
            }
            let Some((k, v)) = l.split_once(':') else {
                continue;
            };
            let v = v.trim();
            let list = || {
                v.split([',', ' '])
                    .filter(|x| !x.is_empty())
                    .map(String::from)
                    .collect()
            };
            match k.trim() {
                "issuer" => o.issuer = Some(v.trim_end_matches('/').to_string()),
                "cluster" => o.cluster = Some(v.to_string()),
                "port" => o.port = v.parse().ok(),
                "lifetime" => o.lifetime = v.parse().ok(),
                "audiences" => o.audiences = list(),
                "san" => o.san = list(),
                _ => {}
            }
        }
        o
    }
    pub fn load(p: &Paths) -> Settings {
        std::fs::read_to_string(p.settings())
            .map(|s| Settings::parse(&s))
            .unwrap_or_default()
    }
}

pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._:".contains(c))
        && !s.starts_with('.')
}

/// Registered audiences: audiences.d/<aud>.json plus operator ones (R16).
pub fn audiences(p: &Paths, s: &Settings) -> Vec<String> {
    let mut v: Vec<String> = s
        .audiences
        .iter()
        .filter(|a| valid_name(a))
        .cloned()
        .collect();
    if let Ok(rd) = std::fs::read_dir(p.audiences()) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if let Some(a) = n.strip_suffix(".json") {
                if valid_name(a) {
                    v.push(a.to_string());
                }
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

/// Per-guest mode (R24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Auto,
    Vsock,
    Push,
    Off,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        Some(match s {
            "auto" => Mode::Auto,
            "vsock" => Mode::Vsock,
            "push" => Mode::Push,
            "off" => Mode::Off,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::Vsock => "vsock",
            Mode::Push => "push",
            Mode::Off => "off",
        }
    }
}

/// guests.cfg: `<vmid>: <mode>` lines, only non-default entries.
pub fn load_modes(p: &Paths) -> BTreeMap<u32, Mode> {
    let mut m = BTreeMap::new();
    if let Ok(s) = std::fs::read_to_string(p.guests_cfg()) {
        for l in s.lines() {
            if let Some((k, v)) = l.split_once(':') {
                if let (Ok(id), Some(md)) = (k.trim().parse(), Mode::parse(v.trim())) {
                    m.insert(id, md);
                }
            }
        }
    }
    m
}

/// Identity generation per guest (R12, R21): random, minted by the
/// reconciler of the owning node, one file per guest (single writer).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenRecord {
    pub gen: String,
    pub pool: String,
    pub kind: String,
    #[serde(default)]
    pub uuid: String,
    pub minted: u64,
}

pub fn gen_path(p: &Paths, vmid: u32) -> PathBuf {
    p.gen_dir().join(format!("{vmid}.json"))
}
pub fn load_gen(p: &Paths, vmid: u32) -> Option<GenRecord> {
    std::fs::read(gen_path(p, vmid))
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
}
pub fn save_gen(p: &Paths, vmid: u32, g: &GenRecord) -> crate::Result<()> {
    std::fs::create_dir_all(p.gen_dir())?;
    crate::write_atomic(&gen_path(p, vmid), &serde_json::to_vec(g)?, 0o600)?;
    Ok(())
}
pub fn drop_gen(p: &Paths, vmid: u32) {
    let _ = std::fs::remove_file(gen_path(p, vmid));
}
pub fn mint_gen() -> String {
    let mut r = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut r);
    crate::jwt::b64(&r)
}

/// issuers.d/pve.json content (R15, D13).
pub fn issuer_doc(
    iss: &str,
    cluster: &str,
    ks: &crate::keys::KeySet,
) -> crate::Result<serde_json::Value> {
    let thumbs: Vec<_> = ks.keys.iter().filter_map(|k| k.thumbprint()).collect();
    Ok(serde_json::json!({
        "name": "pve",
        "issuer": iss,
        "cluster": cluster,
        "schema": crate::claims::SCHEMA,
        "sub_format": format!("spiffe://{cluster}/pool/<pool>/<kind>/<vmid>"),
        "algorithms": ["ES256"],
        "jwks": ks.jwks()?,
        "thumbprints": thumbs,
        "discovery": format!("{iss}/.well-known/openid-configuration"),
    }))
}

/// Write `path` only if the content differs (pmxcfs writes are cluster-wide).
pub fn write_if_changed(path: &Path, data: &[u8], mode: u32) -> crate::Result<bool> {
    if std::fs::read(path).map(|d| d == data).unwrap_or(false) {
        return Ok(false);
    }
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    crate::write_atomic(path, data, mode)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_and_audiences() {
        let s = Settings::parse("issuer: https://x:8443/\naudiences: sts.amazonaws.com, bad/aud\n");
        assert_eq!(s.issuer.as_deref(), Some("https://x:8443"));
        let d = std::env::temp_dir().join(format!("pvei-{}", std::process::id()));
        let p = Paths::new(&d);
        std::fs::create_dir_all(p.audiences()).unwrap();
        std::fs::write(p.audiences().join("s3.json"), "{}").unwrap();
        std::fs::write(p.audiences().join("junk.txt"), "{}").unwrap();
        assert_eq!(audiences(&p, &s), vec!["s3", "sts.amazonaws.com"]);
        std::fs::write(p.guests_cfg(), "101: off\n102: push\n103: bogus\n").unwrap();
        let m = load_modes(&p);
        assert_eq!(m.get(&101), Some(&Mode::Off));
        assert_eq!(m.get(&103), None);
        std::fs::remove_dir_all(d).unwrap();
    }
}
