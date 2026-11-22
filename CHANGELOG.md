# Changelog

All notable changes to this project are documented here
([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)).

## [Unreleased]

### Added
- `pve-identityd`: per-host issuer (ES256 JWT), vsock channel with
  privileged-port check, per-container socket and token files, QEMU guest
  agent push, reconciler (vsock device / container mount / identity
  generation), HTTPS OIDC discovery + JWKS with cluster-CA certificates.
- `pve-identity` CLI: `init`, `rotate`, `status`, `issue`, `verify`.
- Guest agent (`pve-identity-agent`, static Linux binary).
- API `/cluster/identity` (status, guest list, per-guest mode), Datacenter
  panel and "Identity" row in VM/CT Options.
- Registry in `/etc/pve/identity/` for relying-party products.
