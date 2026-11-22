//! Read-only parsers for PVE cluster files in pmxcfs.
use crate::claims::Kind;
use std::collections::BTreeMap;
use std::path::Path;

pub const VSOCK_PREFIX: &str = "-device vhost-vsock-pci,";

#[derive(Debug, Clone, PartialEq)]
pub struct VmEntry {
    pub node: String,
    pub kind: Kind,
}

/// /etc/pve/.vmlist → vmid → (node, kind)
pub fn vmlist(root: &Path) -> BTreeMap<u32, VmEntry> {
    let mut m = BTreeMap::new();
    let Ok(d) = std::fs::read(root.join(".vmlist")) else {
        return m;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&d) else {
        return m;
    };
    if let Some(ids) = v["ids"].as_object() {
        for (id, e) in ids {
            let kind = match e["type"].as_str() {
                Some("qemu") => Kind::Qemu,
                Some("lxc") => Kind::Lxc,
                _ => continue,
            };
            if let (Ok(id), Some(node)) = (id.parse(), e["node"].as_str()) {
                m.insert(
                    id,
                    VmEntry {
                        node: node.into(),
                        kind,
                    },
                );
            }
        }
    }
    m
}

/// user.cfg `pool:<id>:<comment>:<vms>:<storage>:<network>:` → vmid → pool
pub fn pools(user_cfg: &str) -> BTreeMap<u32, String> {
    let mut m = BTreeMap::new();
    for l in user_cfg.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 4 && f[0] == "pool" {
            for id in f[3].split(',').filter_map(|x| x.trim().parse::<u32>().ok()) {
                m.insert(id, f[1].to_string());
            }
        }
    }
    m
}

/// sdn/vnets.cfg → vnet → zone
pub fn vnet_zones(s: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut cur: Option<String> = None;
    for l in s.lines() {
        if let Some(v) = l.strip_prefix("vnet:") {
            cur = Some(v.trim().to_string());
        } else if let (Some(v), Some(z)) = (&cur, l.trim().strip_prefix("zone ")) {
            m.insert(v.clone(), z.trim().to_string());
        } else if l.trim().is_empty() {
            cur = None;
        }
    }
    m
}

pub fn cluster_name(corosync: &str) -> Option<String> {
    corosync.lines().find_map(|l| {
        l.trim()
            .strip_prefix("cluster_name:")
            .map(|v| v.trim().to_string())
    })
}

/// Main section of a guest config (before the first `[section]`).
#[derive(Debug, Clone, Default)]
pub struct GuestConf {
    pub lines: Vec<(String, String)>,
    pub pending: Vec<(String, String)>,
    pub delete_pending: Vec<String>,
}

impl GuestConf {
    pub fn parse(s: &str) -> GuestConf {
        let mut c = GuestConf::default();
        let mut section = "";
        for l in s.lines() {
            if l.starts_with('[') {
                section = if l.starts_with("[PENDING]") {
                    "pending"
                } else {
                    "other"
                };
                continue;
            }
            if l.starts_with('#') {
                continue;
            }
            let Some((k, v)) = l.split_once(':') else {
                continue;
            };
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            match section {
                "" => c.lines.push((k, v)),
                "pending" if k == "delete" => c
                    .delete_pending
                    .extend(v.split(',').map(|x| x.trim().to_string())),
                "pending" => c.pending.push((k, v)),
                _ => {}
            }
        }
        c
    }
    pub fn get(&self, k: &str) -> Option<&str> {
        self.lines
            .iter()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.as_str())
    }
    /// Value as it will be after the next restart (pending applied).
    pub fn effective(&self, k: &str) -> Option<&str> {
        if self.delete_pending.iter().any(|d| d == k) {
            return None;
        }
        self.pending
            .iter()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.as_str())
            .or_else(|| self.get(k))
    }
    pub fn tags(&self) -> Vec<String> {
        self.get("tags")
            .map(|t| {
                t.split([';', ',', ' '])
                    .filter(|x| !x.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn bridges(&self) -> Vec<String> {
        self.lines
            .iter()
            .filter(|(k, _)| k.starts_with("net") && k[3..].chars().all(|c| c.is_ascii_digit()))
            .filter_map(|(_, v)| {
                v.split(',')
                    .find_map(|p| p.strip_prefix("bridge=").map(String::from))
            })
            .collect()
    }
    pub fn smbios_uuid(&self) -> Option<String> {
        self.get("smbios1")?
            .split(',')
            .find_map(|p| p.strip_prefix("uuid=").map(String::from))
    }
    pub fn is_template(&self) -> bool {
        self.get("template") == Some("1")
    }
}

/// CID of a vsock device in a QEMU `args` string.
pub fn vsock_cid(args: &str) -> Option<u32> {
    let i = args.find(VSOCK_PREFIX)?;
    let dev = args[i..].split_whitespace().nth(1)?;
    dev.split(',')
        .find_map(|p| p.strip_prefix("guest-cid="))
        .and_then(|c| c.parse().ok())
}

/// Ensure `args` carries a vsock device with CID = vmid, reusing an existing
/// one (pve-k8s) and preserving all other arguments (R23).
pub fn ensure_vsock(args: &str, vmid: u32) -> String {
    let toks: Vec<&str> = args.split_whitespace().collect();
    let mut out: Vec<String> = Vec::new();
    let mut found = false;
    let mut i = 0;
    while i < toks.len() {
        if toks[i] == "-device" && i + 1 < toks.len() && toks[i + 1].starts_with("vhost-vsock-pci,")
        {
            if !found {
                let parts: Vec<String> = toks[i + 1]
                    .split(',')
                    .map(|p| {
                        if p.starts_with("guest-cid=") {
                            format!("guest-cid={vmid}")
                        } else {
                            p.to_string()
                        }
                    })
                    .collect();
                let mut dev = parts.join(",");
                if !dev.contains("guest-cid=") {
                    dev.push_str(&format!(",guest-cid={vmid}"));
                }
                out.push("-device".into());
                out.push(dev);
                found = true;
            }
            i += 2;
            continue;
        }
        out.push(toks[i].to_string());
        i += 1;
    }
    if !found {
        out.push("-device".into());
        out.push(format!("vhost-vsock-pci,id=vsock0,guest-cid={vmid}"));
    }
    out.join(" ")
}

/// Remove the vsock device we added (id=vsock0 only; pve-k8s devices with a
/// different id are left alone).
pub fn remove_vsock(args: &str) -> String {
    let toks: Vec<&str> = args.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if toks[i] == "-device"
            && i + 1 < toks.len()
            && toks[i + 1].starts_with("vhost-vsock-pci,id=vsock0,")
        {
            i += 2;
            continue;
        }
        out.push(toks[i]);
        i += 1;
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pool_parse() {
        let m = pools("user:root@pam:1:0::::::\npool:t1:c:101,102:local:\npool:t2:::::\n");
        assert_eq!(m.get(&101).map(String::as_str), Some("t1"));
        assert_eq!(m.len(), 2);
    }
    #[test]
    fn vsock_args() {
        assert_eq!(
            ensure_vsock("", 101),
            "-device vhost-vsock-pci,id=vsock0,guest-cid=101"
        );
        assert_eq!(
            ensure_vsock(
                "-cpu host -device vhost-vsock-pci,id=vsock0,guest-cid=9000",
                101
            ),
            "-cpu host -device vhost-vsock-pci,id=vsock0,guest-cid=101"
        );
        let a = ensure_vsock("-device vhost-vsock-pci,id=k8s,guest-cid=7", 105);
        assert_eq!(a, "-device vhost-vsock-pci,id=k8s,guest-cid=105");
        assert_eq!(vsock_cid(&a), Some(105));
        assert_eq!(ensure_vsock(&a, 105), a, "idempotent");
        assert_eq!(
            remove_vsock("-cpu host -device vhost-vsock-pci,id=vsock0,guest-cid=1"),
            "-cpu host"
        );
    }
    #[test]
    fn conf_parse() {
        let c = GuestConf::parse(
            "tags: a;b\nnet0: virtio=AA,bridge=vnet1,firewall=1\nargs: x\n[PENDING]\nargs: y\n[snap]\nargs: z\n",
        );
        assert_eq!(c.tags(), vec!["a", "b"]);
        assert_eq!(c.bridges(), vec!["vnet1"]);
        assert_eq!(c.get("args"), Some("x"));
        assert_eq!(c.effective("args"), Some("y"));
    }
}
