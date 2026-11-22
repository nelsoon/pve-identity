//! Token claims (spec R2/R3). All `pve` scalars are strings.
use serde::{Deserialize, Serialize};

pub const MAX_LIFETIME: u64 = 600;
pub const SCHEMA: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Qemu,
    Lxc,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Qemu => "qemu",
            Kind::Lxc => "lxc",
        }
    }
}

/// Host-side truth about a guest, never asserted by the guest.
#[derive(Debug, Clone)]
pub struct Guest {
    pub cluster: String,
    pub kind: Kind,
    pub vmid: u32,
    pub node: String,
    pub pool: Option<String>,
    pub gen: Option<String>,
    pub zones: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PveClaims {
    pub cluster: String,
    pub kind: String,
    pub vmid: String,
    pub node: String,
    pub pool: String,
    pub gen: String,
    pub zones: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub jti: String,
    pub pve: PveClaims,
}

pub fn subject(cluster: &str, pool: &str, kind: &Kind, vmid: u32) -> String {
    format!("spiffe://{cluster}/pool/{pool}/{}/{vmid}", kind.as_str())
}

/// Build claims; refuses guests without pool or gen (R11, R12).
pub fn build(g: &Guest, iss: &str, aud: &str, now: u64, lifetime: u64) -> crate::Result<Claims> {
    let pool = g
        .pool
        .as_deref()
        .ok_or_else(|| crate::Error::Refused(format!("guest {} not in a pool", g.vmid)))?;
    let gen = g
        .gen
        .as_deref()
        .ok_or_else(|| crate::Error::Refused(format!("guest {} has no identity yet", g.vmid)))?;
    let lifetime = lifetime.clamp(60, MAX_LIFETIME);
    let mut jti = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut jti);
    Ok(Claims {
        iss: iss.to_string(),
        sub: subject(&g.cluster, pool, &g.kind, g.vmid),
        aud: aud.to_string(),
        iat: now,
        nbf: now.saturating_sub(5),
        exp: now + lifetime,
        jti: crate::jwt::b64(&jti),
        pve: PveClaims {
            cluster: g.cluster.clone(),
            kind: g.kind.as_str().into(),
            vmid: g.vmid.to_string(),
            node: g.node.clone(),
            pool: pool.into(),
            gen: gen.into(),
            zones: g.zones.clone(),
            tags: g.tags.clone(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn guest(pool: Option<&str>) -> Guest {
        Guest {
            cluster: "lab".into(),
            kind: Kind::Qemu,
            vmid: 101,
            node: "cloud1".into(),
            pool: pool.map(Into::into),
            gen: Some("g1".into()),
            zones: vec![],
            tags: vec!["web".into()],
        }
    }
    #[test]
    fn sub_format() {
        let c = build(&guest(Some("t1")), "https://i", "s3", 1000, 300).unwrap();
        assert_eq!(c.sub, "spiffe://lab/pool/t1/qemu/101");
        assert_eq!(c.exp, 1300);
        assert_eq!(c.pve.vmid, "101");
    }
    #[test]
    fn no_pool_refused() {
        assert!(matches!(build(&guest(None), "i", "s3", 0, 300), Err(crate::Error::Refused(_))));
    }
    #[test]
    fn lifetime_capped() {
        let c = build(&guest(Some("t1")), "i", "s3", 0, 99999).unwrap();
        assert_eq!(c.exp, MAX_LIFETIME);
    }
    #[test]
    fn scalars_are_strings() {
        let c = build(&guest(Some("t1")), "i", "s3", 0, 300).unwrap();
        let v = serde_json::to_value(&c).unwrap();
        for (_, x) in v["pve"].as_object().unwrap() {
            assert!(x.is_string() || x.is_array());
        }
    }
}
