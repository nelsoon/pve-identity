// "Identity" row in the VM and CT Options tabs (spec R24, plan D12).
// Mode lives in /etc/pve/identity/guests.cfg, not in the guest config,
// so the row reads/writes /cluster/identity/guests/{vmid}.
Ext.define('PVE.identity.ModeEdit', {
    extend: 'Proxmox.window.Edit',
    alias: 'widget.pveIdentityModeEdit',

    subject: gettext('Identity'),
    width: 420,

    initComponent: function() {
        let me = this;
        let vmid = me.pveSelNode.data.vmid;
        let isCt = me.pveSelNode.data.type === 'lxc';
        // run_editor passes the guest config url; the mode has its own API
        me.url = `/api2/extjs/cluster/identity/guests/${vmid}`;
        me.method = 'PUT';
        let modes = isCt
            ? [['auto', gettext('Automatic (socket + token files)')], ['off', gettext('Off')]]
            : [
                ['auto', gettext('Automatic (vsock, guest agent fallback)')],
                ['vsock', 'vsock'],
                ['push', gettext('Guest agent push (no vsock device)')],
                ['off', gettext('Off')],
            ];
        me.items = [
            {
                xtype: 'proxmoxKVComboBox',
                name: 'mode',
                fieldLabel: gettext('Mode'),
                value: 'auto',
                comboItems: modes,
            },
            {
                xtype: 'displayfield',
                userCls: 'pmx-hint',
                value: gettext('Only guests in a pool have an identity. Changes to channels apply at the next guest restart.'),
            },
        ];
        me.callParent();
        me.load();
    },
});

Ext.define('PVE.identity.OptionsRow', {
    singleton: true,

    modeText: {
        auto: gettext('Automatic'),
        vsock: 'vsock',
        push: gettext('Guest agent push'),
        off: gettext('Off'),
    },

    attach: function(grid) {
        let vmid = grid.pveSelNode.data.vmid;
        let caps = Ext.state.Manager.get('GuiCap');
        if (!grid.rows || !vmid) {
            return;
        }
        grid.rows.pveidentity = {
            header: gettext('Identity'),
            defaultValue: 'auto',
            renderer: () => {
                if (grid.pveIdentityMode === undefined) {
                    return Proxmox.Utils.unknownText;
                }
                return PVE.identity.OptionsRow.modeText[grid.pveIdentityMode] || grid.pveIdentityMode;
            },
            editor: caps.vms['VM.Config.Options'] ? 'PVE.identity.ModeEdit' : undefined,
        };
        let refresh = () => Proxmox.Utils.API2Request({
            url: `/cluster/identity/guests/${vmid}`,
            method: 'GET',
            success: (resp) => {
                grid.pveIdentityMode = resp.result.data.mode;
                if (!grid.isDestroyed) {
                    grid.getView().refresh();
                }
            },
            failure: () => {
                // pve-identity API absent: hide the row
                grid.rows.pveidentity.visible = false;
                grid.getStore().filter();
            },
        });
        grid.mon(grid.rstore, 'load', refresh);
        // a row added after init must be seeded into the diff store once
        grid.getStore().add({ key: 'pveidentity', value: 'auto' });
    },
});

Ext.define(null, {
    override: 'PVE.qemu.Options',
    initComponent: function() {
        this.callParent(arguments);
        PVE.identity.OptionsRow.attach(this);
    },
});

Ext.define(null, {
    override: 'PVE.lxc.Options',
    initComponent: function() {
        this.callParent(arguments);
        PVE.identity.OptionsRow.attach(this);
    },
});
