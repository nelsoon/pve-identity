# AGENTS.md

- Rust workspace: `crates/core` (claims, JWT, keys, registry, PVE config
  parsing), `crates/daemon` (`pve-identityd`, `pve-identity`),
  `crates/agent` (guest agent). Perl API in `PVE/`, ExtJS in `www/`,
  packaging in `debian/` + `Makefile`.
- Gate: `make lint test`. Never weaken a test to make it pass.
- Security rules: a guest never asserts its own identity; the pool is the
  tenant boundary; never log tokens or keys.
