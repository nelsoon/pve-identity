# Relying-party contract

How products and services consume pve-identity. pve-identity never writes
another product's configuration; each product reads the registry and
configures itself.

## Registry (`/etc/pve/identity/`, in pmxcfs)

| Path | Writer | Content |
|---|---|---|
| `issuers.d/pve.json` | pve-identityd | this cluster's issuer: `issuer`, `cluster`, `jwks` (current, next, previous keys, each with `x5c`), `thumbprints` (SHA-1 of each key certificate), `sub_format`, `schema` |
| `issuers.d/<name>.json` | other products | e.g. one per Kubernetes cluster (service-account issuer + pool) |
| `audiences.d/<aud>.json` | relying-party products | registers an audience; tokens are only issued for registered audiences |
| `guests.cfg` | API | per-guest mode (non-default only) |

Detection: `issuers.d/pve.json` present = pve-identity enabled. Removed on
package purge. Reload on file change; no network fetch is needed on the
cluster.

## Trust rules

- Bind on `sub` (`spiffe://<cluster>/pool/<pool>/<kind>/<vmid>`) or on the
  `pve.pool` claim. The pool is the tenant boundary.
- Do not use `pve.tags` or `pve.zones` for cross-tenant decisions: tenants can
  edit them.
- Always check `aud`, `exp` and the signature. `gen` changes when a guest is
  re-created or changes pool.

## OpenBao (`jwt` auth)

Static keys from the registry (no network):

```sh
bao auth enable -path=pve jwt
bao write auth/pve/config \
    jwt_validation_pubkeys=@keys.pem bound_issuer="$(jq -r .issuer pve.json)"
bao write auth/pve/role/teama role_type=jwt user_claim=sub \
    bound_audiences=openbao \
    bound_claims_type=string bound_claims='{"/pve/pool":"teama"}' \
    claim_mappings='{"/pve/vmid":"vmid","/pve/pool":"pool"}' \
    token_policies=teama
```

Or by URL: `oidc_discovery_url=<issuer>` with `oidc_discovery_ca_pem` set to
the PVE cluster CA. All `pve` scalar claims are strings, as `claim_mappings`
requires.

## Ceph RGW STS (`AssumeRoleWithWebIdentity`)

RGW fetches discovery and JWKS from the issuer URL and needs:

1. The PVE cluster CA in the RGW host's system trust store (RGW has no
   per-provider CA setting).
2. An OIDC provider per tenant account with `Url` = `issuer`, client id `s3`
   and every value of `thumbprints` from `pve.json` (update on rotation; the
   next thumbprint is published before its key signs).
3. Role trust conditions on `sub` / `aud` only (RGW does not evaluate nested
   claims), e.g. `StringLike <provider>:sub spiffe://<cluster>/pool/teama/*`.

ES256 only (RGW rejects EdDSA).

## Kubernetes workloads

Pods use their own Kubernetes service-account tokens (the cluster's issuer is
registered in `issuers.d/` by the Kubernetes product), never the node VM's
identity. The agent socket and files are root/group restricted and the host
only answers vsock requests from a privileged source port, so a workload
inside a guest cannot obtain the guest's token by default.

## External clouds

AWS, GCP and Azure accept an external OIDC issuer by URL: the issuer must be
publicly reachable with a publicly trusted certificate (reverse proxy or ACME)
and the audience (e.g. `sts.amazonaws.com`) listed in `/etc/pve/identity.cfg`.
