# Integration with Proxmox VE

The package needs three small integration points in stock pve-manager files,
applied by the maintainer scripts (`debian/integrate.pl`, embedded into
postinst/postrm): idempotent, atomic writes, skipped with a warning when an
anchor no longer matches, removed on uninstall, re-applied by a dpkg trigger
when pve-manager replaces the files. The outcome is recorded in
`/var/lib/pve-identity/integration.status`.

1. API registration in `PVE/API2/Cluster.pm`, after the Ceph child:

   ```perl
   use PVE::API2::Cluster::Identity;
   __PACKAGE__->register_method({
       subclass => "PVE::API2::Cluster::Identity",
       path => 'identity',
   });
   ```

2. Script tag in `index.html.tpl` loading `/pve2/js/PVEIdentity.js` after
   `pvemanagerlib.js`, with a content-hash `ver` suffix.

3. Datacenter navigation entry "Identity" in `pvemanagerlib.js`, between
   `// pve-identity:begin` / `// pve-identity:end` markers.

The "Identity" row in the VM and CT Options tabs needs no file patch: it is an
ExtJS override of `PVE.qemu.Options` / `PVE.lxc.Options` shipped in
`PVEIdentity.js`, and hides itself when the API is absent.

If the API registration fails, the UI points are removed so the panel is
hidden rather than broken. Re-check after every pve-manager upgrade.
