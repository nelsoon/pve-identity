VERSION := 0.1.2-1
TARGET  := x86_64-unknown-linux-musl
REL     := target/$(TARGET)/release
BUILD   := build
MGR     := pve-identity-manager
AGENT   := pve-identity-agent
MGR_DEB := $(BUILD)/$(MGR)_$(VERSION)_amd64.deb
AG_DEB  := $(BUILD)/$(AGENT)_$(VERSION)_amd64.deb
JS      := $(sort $(wildcard www/manager6/identity/*.js))
MS      := $(BUILD)/mgr
AS      := $(BUILD)/agent

.PHONY: all lint test bin deb clean

all: lint test deb

lint:
	cargo fmt --check
	cargo clippy -q --all-targets -- -D warnings
	perl -c debian/integrate.pl
	@for f in $(JS); do node --check $$f || exit 1; done
	@cat debian/postinst.head debian/integrate.pl debian/postinst.tail | sh -n
	@cat debian/postrm.head debian/integrate.pl debian/postrm.tail | sh -n
	@echo "lint ok"

test:
	cargo test -q

bin:
	CC_x86_64_unknown_linux_musl=$${CC:-cc} cargo build -q --release --target $(TARGET)

deb: bin
	rm -rf $(MS) $(AS)
	install -d $(MS)/DEBIAN $(MS)/usr/sbin $(MS)/usr/share/perl5/PVE/API2/Cluster \
	  $(MS)/usr/share/pve-manager/js $(MS)/lib/systemd/system
	install -m755 $(REL)/pve-identityd $(REL)/pve-identity $(MS)/usr/sbin/
	install -m644 PVE/API2/Cluster/Identity.pm $(MS)/usr/share/perl5/PVE/API2/Cluster/
	cat $(JS) > $(MS)/usr/share/pve-manager/js/PVEIdentity.js
	install -m644 debian/pve-identityd.service $(MS)/lib/systemd/system/
	cat debian/postinst.head debian/integrate.pl debian/postinst.tail > $(MS)/DEBIAN/postinst
	cat debian/postrm.head debian/integrate.pl debian/postrm.tail > $(MS)/DEBIAN/postrm
	install -m755 debian/prerm $(MS)/DEBIAN/prerm
	install -m644 debian/triggers $(MS)/DEBIAN/triggers
	chmod 755 $(MS)/DEBIAN/postinst $(MS)/DEBIAN/postrm
	printf 'Package: $(MGR)\nVersion: $(VERSION)\nArchitecture: amd64\nMaintainer: pve-identity contributors\nDepends: pve-manager, pve-cluster, openssl, perl\nDescription: Guest identity tokens for Proxmox VE\n Every VM and container in a pool gets a short-lived OIDC/JWT identity\n signed by its cluster (vsock, container socket, guest agent push).\n' > $(MS)/DEBIAN/control
	dpkg-deb --root-owner-group --build $(MS) $(MGR_DEB) >/dev/null
	install -d $(AS)/DEBIAN $(AS)/usr/bin $(AS)/lib/systemd/system
	install -m755 $(REL)/pve-identity-agent $(AS)/usr/bin/pve-identity
	install -m644 debian/pve-identity-agent.service $(AS)/lib/systemd/system/
	install -m755 debian/agent/postinst debian/agent/prerm $(AS)/DEBIAN/
	printf 'Package: $(AGENT)\nVersion: $(VERSION)\nArchitecture: amd64\nMaintainer: pve-identity contributors\nDescription: Proxmox guest identity agent\n Keeps /run/pve-identity/<audience>/token fresh from the Proxmox host over\n virtio-vsock. Static binary, any Linux distribution.\n' > $(AS)/DEBIAN/control
	dpkg-deb --root-owner-group --build $(AS) $(AG_DEB) >/dev/null
	@echo "built $(MGR_DEB) $(AG_DEB)"

clean:
	rm -rf $(BUILD)
