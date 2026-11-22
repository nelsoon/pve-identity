// Datacenter -> Identity: issuer, keys, audiences, guest list (read-only).
Ext.define('pve-identity-guest', {
    extend: 'Ext.data.Model',
    fields: ['vmid', 'kind', 'node', 'pool', 'mode', 'channels', 'note', 'last_refresh',
        { name: 'pending_restart', type: 'boolean' }, { name: 'running', type: 'boolean' }],
    idProperty: 'vmid',
});

Ext.define('PVE.identity.View', {
    extend: 'Ext.panel.Panel',
    alias: 'widget.pveIdentityView',

    onlineHelp: undefined,
    layout: { type: 'vbox', align: 'stretch' },
    bodyPadding: 0,

    initComponent: function() {
        let me = this;

        let info = Ext.create('Ext.panel.Panel', {
            title: gettext('Issuer'),
            bodyPadding: 10,
            border: false,
            html: gettext('Loading...'),
        });

        let keys = Ext.create('Ext.grid.Panel', {
            title: gettext('Signing keys'),
            border: false,
            store: { fields: ['kid', 'state', 'alg', 'x5t'] },
            columns: [
                { header: gettext('Key ID'), dataIndex: 'kid', flex: 1 },
                { header: gettext('State'), dataIndex: 'state', width: 100 },
                { header: 'Alg', dataIndex: 'alg', width: 80 },
                { header: 'x5t', dataIndex: 'x5t', flex: 1 },
            ],
        });

        let guestStore = Ext.create('Proxmox.data.UpdateStore', {
            storeid: 'pve-identity-guests',
            interval: 10000,
            model: 'pve-identity-guest',
            proxy: { type: 'proxmox', url: '/api2/json/cluster/identity/guests' },
            sorters: 'vmid',
        });

        let guests = Ext.create('Ext.grid.Panel', {
            title: gettext('Guests'),
            border: false,
            flex: 1,
            store: guestStore,
            columns: [
                { header: 'ID', dataIndex: 'vmid', width: 80 },
                { header: gettext('Type'), dataIndex: 'kind', width: 70 },
                { header: gettext('Node'), dataIndex: 'node', width: 100 },
                { header: gettext('Pool'), dataIndex: 'pool', width: 100,
                  renderer: v => v || `<i>${gettext('none (no identity)')}</i>` },
                { header: gettext('Mode'), dataIndex: 'mode', width: 80 },
                { header: gettext('Channels'), dataIndex: 'channels', flex: 1 },
                { header: gettext('Pending restart'), dataIndex: 'pending_restart', width: 120,
                  renderer: Proxmox.Utils.format_boolean },
                { header: gettext('Last refresh'), dataIndex: 'last_refresh', flex: 1,
                  renderer: (v, m, rec) => Ext.htmlEncode(v || rec.data.note || '') },
            ],
        });

        let load = function() {
            Proxmox.Utils.API2Request({
                url: '/cluster/identity/status',
                method: 'GET',
                failure: (r) => info.update(Ext.htmlEncode(r.htmlStatus)),
                success: function(resp) {
                    let d = resp.result.data;
                    if (!d.enabled) {
                        info.update(gettext('Not initialized. Run "pve-identity init --issuer https://NAME" on a node.'));
                        return;
                    }
                    let e = Ext.htmlEncode;
                    info.update(`<table class="pmx-table">`
                        + `<tr><td>${gettext('Issuer')}</td><td><code>${e(d.issuer)}</code></td></tr>`
                        + `<tr><td>${gettext('Cluster')}</td><td>${e(d.cluster)}</td></tr>`
                        + `<tr><td>${gettext('Subject')}</td><td><code>${e(d.sub_format)}</code></td></tr>`
                        + `<tr><td>${gettext('Audiences')}</td><td>${e((d.audiences || []).join(', ') || '-')}</td></tr>`
                        + `<tr><td>${gettext('Thumbprints')}</td><td><code>${e((d.thumbprints || []).join(' '))}</code></td></tr>`
                        + `</table>`);
                    keys.getStore().loadData(d.keys || []);
                },
            });
        };

        Ext.apply(me, {
            items: [info, keys, guests],
            listeners: {
                activate: () => { load(); guestStore.startUpdate(); },
                deactivate: () => guestStore.stopUpdate(),
                destroy: () => guestStore.stopUpdate(),
            },
        });
        me.callParent();
    },
});
