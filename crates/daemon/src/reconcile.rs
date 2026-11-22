//! Reconciler (R23/R24, D10): no PVE create/update hook exists, so every
//! host watches /etc/pve/.version and converges the guests it owns.
use crate::ct::{self, CtSockets};
use crate::ctx::Ctx;
use crate::vsock;
use pve_identity_core::claims::Kind;
use pve_identity_core::keys::{KeySet, State};
use pve_identity_core::registry::{self, GenRecord, Mode};
use pve_identity_core::{now, pvecfg};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Default)]
pub struct RecState {
    last_version: String,
    /// vmid -> next refresh time (push / CT files)
    next_refresh: BTreeMap<u32, u64>,
    /// vmid -> (qemu pid, os id)
    os: BTreeMap<u32, (String, String)>,
    status: BTreeMap<u32, serde_json::Value>,
    last_full: u64,
}

pub struct Reconciler {
    pub ctx: Arc<Ctx>,
    pub cts: CtSockets,
    st: std::sync::Mutex<RecState>,
}

fn added_marker(ctx: &Ctx, vmid: u32) -> PathBuf {
    ctx.paths.private().join("added").join(vmid.to_string())
}

fn qemu_pid(vmid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/var/run/qemu-server/{vmid}.pid")).ok().map(|s| s.trim().to_string())
        .filter(|p| std::path::Path::new(&format!("/proc/{p}")).exists())
}

fn ct_running(vmid: u32) -> bool {
    std::path::Path::new(&format!("/sys/fs/cgroup/lxc/{vmid}")).exists()
}

/// Set/remove raw lxc.mount.entry under the PVE config lock.
fn lxc_mount(vmid: u32, add: bool) -> Result<(), String> {
    let entry = ct::mount_entry(vmid);
    let script = r#"
use strict; use PVE::LXC::Config;
my ($id, $entry, $add) = @ARGV;
PVE::LXC::Config->lock_config($id, sub {
  my $c = PVE::LXC::Config->load_config($id);
  my @l = grep { !($_->[0] eq 'lxc.mount.entry' && $_->[1] =~ m{^/run/pve-identity/ct/}) } @{$c->{lxc} // []};
  push @l, ['lxc.mount.entry', $entry] if $add;
  $c->{lxc} = \@l;
  PVE::LXC::Config->write_config($id, $c);
});
"#;
    crate::run("perl", &["-e", script, &vmid.to_string(), &entry, if add { "1" } else { "0" }]).map(|_| ())
}

fn qm_set_args(vmid: u32, args: &str) -> Result<(), String> {
    if args.trim().is_empty() {
        crate::run("qm", &["set", &vmid.to_string(), "--delete", "args"]).map(|_| ())
    } else {
        crate::run("qm", &["set", &vmid.to_string(), "--args", args]).map(|_| ())
    }
}

impl Reconciler {
    pub fn new(ctx: Arc<Ctx>) -> Reconciler {
        Reconciler { ctx, cts: CtSockets::default(), st: Default::default() }
    }

    /// One pass; cheap when nothing changed (only refresh timers run).
    pub fn tick(&self) {
        let ver = std::fs::read_to_string(self.ctx.paths.root.join(".version")).unwrap_or_default();
        let t = now();
        let changed = {
            let mut st = self.st.lock().unwrap();
            let c = st.last_version != ver || t >= st.last_full + 30;
            if c {
                st.last_version = ver;
                st.last_full = t;
            }
            c
        };
        if changed {
            self.ctx.reload();
            self.keys_and_registry();
            self.converge();
        }
        self.refresh(t);
    }

    /// Key rotation steps + issuers.d/pve.json (any host; idempotent).
    fn keys_and_registry(&self) {
        let ctx = &self.ctx;
        let Some(iss) = ctx.issuer() else { return };
        let mut ks = KeySet::load(&ctx.paths.keys()).unwrap_or_default();
        let mut dirty = ks.advance(now());
        for k in ks.keys.iter_mut().filter(|k| k.cert.is_empty()) {
            match crate::cert::key_cert(k, &ctx.cluster()) {
                Ok(c) => {
                    k.cert = c;
                    dirty = true;
                }
                Err(e) => crate::log(format!("key {}: cert: {e}", k.kid)),
            }
        }
        if dirty {
            if let Err(e) = ks.save(&ctx.paths.keys()) {
                crate::log(format!("save keys: {e}"));
            }
            *ctx.keys.write().unwrap() = ks.clone();
        }
        if ks.keys.is_empty() {
            return;
        }
        match registry::issuer_doc(&iss, &ctx.cluster(), &ks) {
            Ok(doc) => {
                let data = serde_json::to_vec_pretty(&doc).unwrap_or_default();
                if let Ok(true) = registry::write_if_changed(&ctx.paths.pve_json(), &data, 0o644) {
                    crate::log("registry: issuers.d/pve.json updated");
                }
            }
            Err(e) => crate::log(format!("issuer doc: {e}")),
        }
    }

    fn converge(&self) {
        let ctx = &self.ctx;
        let root = &ctx.paths.root;
        let vl = pvecfg::vmlist(root);
        let pools = pvecfg::pools(&std::fs::read_to_string(root.join("user.cfg")).unwrap_or_default());
        let modes = registry::load_modes(&ctx.paths);
        let mut status = BTreeMap::new();

        // Destroyed guests: drop gen + marker (any host may do it).
        if let Ok(rd) = std::fs::read_dir(ctx.paths.gen_dir()) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if let Some(id) = n.strip_suffix(".json").and_then(|x| x.parse::<u32>().ok()) {
                    if !vl.contains_key(&id) {
                        registry::drop_gen(&ctx.paths, id);
                        let _ = std::fs::remove_file(added_marker(ctx, id));
                        crate::log(format!("guest {id}: destroyed, identity dropped"));
                    }
                }
            }
        }

        let mut want_ct_dirs = BTreeSet::new();
        for (&vmid, e) in &vl {
            let pool = pools.get(&vmid).cloned();
            let mode = modes.get(&vmid).copied().unwrap_or_default();
            let active = pool.is_some() && mode != Mode::Off;
            if e.kind == Kind::Lxc && active {
                want_ct_dirs.insert(vmid);
                self.cts.ensure(&self.ctx, vmid, e.node == ctx.node);
            }
            if e.node != ctx.node {
                continue;
            }
            let path = ctx.conf_path(&e.node, &e.kind, vmid);
            let Ok(raw) = std::fs::read_to_string(&path) else { continue };
            let conf = pvecfg::GuestConf::parse(&raw);
            if conf.is_template() {
                continue;
            }
            let mut s = json!({"vmid": vmid, "kind": e.kind.as_str(), "node": e.node, "pool": pool,
                "mode": mode.as_str(), "channels": [], "pending_restart": false});
            if conf.get("lock").is_some() {
                s["note"] = json!("locked, retrying");
                status.insert(vmid, s);
                continue;
            }
            match e.kind {
                Kind::Qemu => self.converge_vm(vmid, &conf, active, mode, &mut s),
                Kind::Lxc => self.converge_ct(vmid, &conf, active, &mut s),
            }
            // gen (R12, R21)
            if active {
                let uuid = conf.smbios_uuid().unwrap_or_default();
                let cur = registry::load_gen(&ctx.paths, vmid);
                let p = pool.clone().unwrap_or_default();
                let keep = cur.as_ref().is_some_and(|g| g.pool == p && g.kind == e.kind.as_str() && (g.uuid == uuid));
                if !keep {
                    let g = GenRecord { gen: registry::mint_gen(), pool: p, kind: e.kind.as_str().into(), uuid, minted: now() };
                    match registry::save_gen(&ctx.paths, vmid, &g) {
                        Ok(()) => crate::log(format!("guest {vmid}: identity minted (pool {})", g.pool)),
                        Err(er) => crate::log(format!("guest {vmid}: gen: {er}")),
                    }
                }
            } else if registry::load_gen(&ctx.paths, vmid).is_some() {
                registry::drop_gen(&ctx.paths, vmid);
                crate::log(format!("guest {vmid}: identity dropped ({})", if pool.is_none() { "no pool" } else { "mode off" }));
            }
            status.insert(vmid, s);
        }

        // CT dirs/sockets no longer wanted
        for id in self.cts.known() {
            if !want_ct_dirs.contains(&id) {
                self.cts.remove(id);
            }
        }
        if let Ok(rd) = std::fs::read_dir(ct::HOST_BASE) {
            for e in rd.flatten() {
                if let Ok(id) = e.file_name().to_string_lossy().parse::<u32>() {
                    if !want_ct_dirs.contains(&id) {
                        self.cts.remove(id);
                    }
                }
            }
        }
        let mut st = self.st.lock().unwrap();
        st.status = status;
        st.next_refresh.retain(|id, _| vl.contains_key(id));
        drop(st);
        self.write_status();
    }

    fn converge_vm(&self, vmid: u32, conf: &pvecfg::GuestConf, active: bool, mode: Mode, s: &mut serde_json::Value) {
        let ctx = &self.ctx;
        let args = conf.effective("args").unwrap_or("").to_string();
        let marker = added_marker(ctx, vmid);
        let want_vsock = active && mode != Mode::Push;
        if want_vsock {
            let new = pvecfg::ensure_vsock(&args, vmid);
            if new != args {
                let had = pvecfg::vsock_cid(&args).is_some();
                match qm_set_args(vmid, &new) {
                    Ok(()) => {
                        crate::log(format!("vm {vmid}: vsock {} (cid {vmid})", if had { "CID fixed" } else { "added" }));
                        if !had {
                            let _ = std::fs::create_dir_all(marker.parent().unwrap());
                            let _ = std::fs::write(&marker, b"");
                        }
                    }
                    Err(e) => crate::log(format!("vm {vmid}: cannot set args: {e}")),
                }
            }
        } else if marker.exists() {
            let new = pvecfg::remove_vsock(&args);
            if new != args {
                match qm_set_args(vmid, &new) {
                    Ok(()) => crate::log(format!("vm {vmid}: vsock removed (applies at restart)")),
                    Err(e) => {
                        crate::log(format!("vm {vmid}: cannot remove vsock: {e}"));
                        return;
                    }
                }
            }
            let _ = std::fs::remove_file(&marker);
        }
        let running = qemu_pid(vmid).is_some();
        let live_vsock = running && vsock::running_cid_matches(vmid);
        let mut ch = vec![];
        if active && live_vsock && mode != Mode::Push {
            ch.push("vsock");
        }
        if active && running && want_vsock && !live_vsock {
            s["pending_restart"] = json!(true);
        }
        if active && running && self.wants_push(vmid, mode, live_vsock) {
            ch.push("qga-push");
        }
        s["running"] = json!(running);
        s["channels"] = json!(ch);
    }

    fn wants_push(&self, vmid: u32, mode: Mode, live_vsock: bool) -> bool {
        match mode {
            Mode::Push => true,
            Mode::Vsock | Mode::Off => false,
            Mode::Auto => {
                if !live_vsock {
                    return true;
                }
                // vsock present: push only for non-Linux guests (osinfo).
                let pid = qemu_pid(vmid).unwrap_or_default();
                let st = self.st.lock().unwrap();
                if let Some((p, os)) = st.os.get(&vmid) {
                    if *p == pid {
                        return os != "linux" && os != "unknown";
                    }
                }
                drop(st);
                match crate::push::osinfo(vmid) {
                    Ok(os) => {
                        let non_linux = os != "linux";
                        self.st.lock().unwrap().os.insert(vmid, (pid, os));
                        non_linux
                    }
                    Err(_) => false,
                }
            }
        }
    }

    fn converge_ct(&self, vmid: u32, conf: &pvecfg::GuestConf, active: bool, s: &mut serde_json::Value) {
        let want = ct::mount_entry(vmid);
        let has_ours: Vec<&str> = conf
            .lines
            .iter()
            .filter(|(k, v)| k == "lxc.mount.entry" && v.starts_with("/run/pve-identity/ct/"))
            .map(|(_, v)| v.as_str())
            .collect();
        let ok = has_ours.len() == 1 && has_ours[0] == want;
        if active && !ok {
            match lxc_mount(vmid, true) {
                Ok(()) => crate::log(format!("ct {vmid}: /dev/pve-identity mount added")),
                Err(e) => crate::log(format!("ct {vmid}: cannot add mount: {e}")),
            }
        } else if !active && !has_ours.is_empty() {
            match lxc_mount(vmid, false) {
                Ok(()) => crate::log(format!("ct {vmid}: /dev/pve-identity mount removed (applies at restart)")),
                Err(e) => crate::log(format!("ct {vmid}: cannot remove mount: {e}")),
            }
        }
        let running = ct_running(vmid);
        s["running"] = json!(running);
        if active {
            s["channels"] = json!(["ct-socket", "ct-files"]);
            if running && !ok {
                s["pending_restart"] = json!(true);
            }
        }
    }

    /// Refresh pushed tokens (VMs) and host-written files (CTs) at half
    /// lifetime.
    fn refresh(&self, t: u64) {
        let due: Vec<(u32, serde_json::Value)> = {
            let st = self.st.lock().unwrap();
            st.status
                .iter()
                .filter(|(id, _)| st.next_refresh.get(id).map(|&n| t >= n).unwrap_or(true))
                .map(|(id, s)| (*id, s.clone()))
                .collect()
        };
        let half = (self.ctx.lifetime() / 2).max(30);
        let mut changed = false;
        for (vmid, s) in due {
            let chans: Vec<String> = s["channels"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            let running = s["running"].as_bool().unwrap_or(false);
            let mut next = t + half;
            let mut result: Option<Result<String, String>> = None;
            if running && chans.iter().any(|c| c == "qga-push") {
                result = Some(crate::push::push(&self.ctx, vmid).map(|os| format!("ok ({os})")));
            } else if running && chans.iter().any(|c| c == "ct-files") && s["kind"] == "lxc" {
                result = Some(ct::write_tokens(&self.ctx, vmid).map(|n| format!("ok ({n} audiences)")));
            }
            if let Some(r) = result {
                if r.is_err() {
                    next = t + 30;
                }
                let txt = r.unwrap_or_else(|e| format!("error: {e}"));
                if txt.starts_with("error") {
                    crate::log(format!("guest {vmid}: refresh {txt}"));
                }
                let mut st = self.st.lock().unwrap();
                if let Some(x) = st.status.get_mut(&vmid) {
                    x["last_refresh"] = json!(txt);
                    x["last_refresh_time"] = json!(t);
                    changed = true;
                }
            }
            self.st.lock().unwrap().next_refresh.insert(vmid, next);
        }
        if changed {
            self.write_status();
        }
    }

    /// Per-node status for the API's guest list (R14 filtering is in API).
    fn write_status(&self) {
        let st = self.st.lock().unwrap();
        let keys = self.ctx.keys.read().unwrap();
        let doc = json!({
            "node": self.ctx.node,
            "issuer": self.ctx.issuer(),
            "current_kid": keys.current().map(|k| k.kid.clone()),
            "next_kid": keys.keys.iter().find(|k| k.state == State::Next).map(|k| k.kid.clone()),
            "guests": st.status.values().map(|v| {
                let mut v = v.clone();
                if let Some(o) = v.as_object_mut() { o.remove("last_refresh_time"); }
                v
            }).collect::<Vec<_>>(),
        });
        let _ = registry::write_if_changed(&self.ctx.paths.node_state(&self.ctx.node), &serde_json::to_vec_pretty(&doc).unwrap_or_default(), 0o640);
    }
}
