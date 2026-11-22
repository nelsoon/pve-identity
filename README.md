# pve-identity

Workload identity for Proxmox VE guests, the way clouds do it: every VM and
container in a resource pool gets a short-lived, signed identity token
(OIDC-style JWT) from its Proxmox cluster, with no secret copied into the
guest and no network needed to obtain it. Relying parties (OpenBao, Ceph RGW
STS, Kubernetes, external clouds) verify it with standard JWT/JWKS.

pve-identity stores no secrets and grants no access: relying parties decide
what an identity may do.

## How a guest gets its identity

| Guest | Channel | In-guest software |
|---|---|---|
| Linux VM | virtio-vsock (CID = VMID, host port 10245) | `pve-identity-agent` |
| VM without vsock (BSD, Windows, appliances) | host pushes token files through the QEMU guest agent | `qemu-guest-agent` |
| LXC container | `/dev/pve-identity/` bind mount: `sock` + `<aud>/token` files | none |

The host identifies the guest from the channel itself (vsock peer CID checked
against the running QEMU process, container socket checked by cgroup); a guest
never asserts its own identity.

Token claims:

```json
{
  "iss": "https://identity.example.net:8443",
  "sub": "spiffe://<cluster>/pool/<pool>/<qemu|lxc>/<vmid>",
  "aud": "s3",
  "exp": 1700000300,
  "pve": { "cluster": "...", "kind": "qemu", "vmid": "101", "node": "...",
           "pool": "...", "gen": "...", "zones": [], "tags": [] }
}
```

- The **pool is the tenant**: only guests in a pool get an identity; moving a
  guest to another pool changes its identity (`sub` and `gen`).
- Tokens live at most 10 minutes (default 5) and are signed with ES256.
- `tags` and `zones` are informational only; never base cross-tenant trust on
  them.

## Install

On every PVE node:

```sh
apt install ./pve-identity-manager_*_amd64.deb
pve-identity init --issuer https://identity.example.net:8443   # once per cluster
```

`pve-identityd` then, on every node:

- adds the vsock device to every VM in a pool (merged into `args`; a running
  VM shows "pending restart" and gets tokens by guest-agent push meanwhile),
- adds the `/dev/pve-identity` mount to every container in a pool,
- publishes the issuer in `/etc/pve/identity/issuers.d/pve.json`,
- serves OIDC discovery and JWKS over HTTPS (certificate from the cluster CA).

In Linux guests:

```sh
apt install ./pve-identity-agent_*_amd64.deb     # or copy the static binary
cat /run/pve-identity/s3/token                   # root or group pve-identity
pve-identity token openbao
```

In containers, no install:

```sh
cat /dev/pve-identity/s3/token
curl --unix-socket /dev/pve-identity/sock 'http://x/v1/token?aud=s3'
```

## Per-guest mode

VM/CT → Options → **Identity**: `auto` (default), `vsock`, `push`, `off`
(containers: `auto`/`off`). API: `PUT /cluster/identity/guests/{vmid}`,
permission `VM.Config.Options` on the guest.

## Audiences

A token is only issued for an audience registered in
`/etc/pve/identity/audiences.d/<aud>.json` (written by the relying-party
products, e.g. `s3`, `openbao`) or listed in `/etc/pve/identity.cfg`
(`audiences: sts.amazonaws.com`).

## Key rotation

```sh
pve-identity rotate
```

The next key (and its certificate thumbprint) is published first and signs
only after a pre-publish delay; the previous key stays published until every
token it signed has expired.

See [docs/relying-parties.md](docs/relying-parties.md) for integrating
OpenBao, Ceph RGW and others, and [INTEGRATION.md](INTEGRATION.md) for the
points where the package hooks into pve-manager.

## Build

```sh
make lint test deb      # Rust (static musl binaries), Perl, ExtJS, .deb
```

## License

AGPL-3.0-or-later.
