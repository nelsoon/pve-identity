package PVE::API2::Cluster::Identity;

# /cluster/identity: read-only issuer status, guest list (R14) and the
# per-guest mode (R24). pve-identityd does the work; this API only reads
# its published state and edits /etc/pve/identity/guests.cfg.

use strict;
use warnings;

use JSON;
use PVE::Cluster;
use PVE::Exception qw(raise_param_exc raise_perm_exc);
use PVE::JSONSchema qw(get_standard_option);
use PVE::RPCEnvironment;
use PVE::Tools qw(file_get_contents file_set_contents);

use base qw(PVE::RESTHandler);

my $REG = '/etc/pve/identity';
my $GUESTS_CFG = "$REG/guests.cfg";
my $MODES = ['auto', 'vsock', 'push', 'off'];

my sub read_json {
    my ($file) = @_;
    return undef if !-f $file;
    my $raw = eval { file_get_contents($file) } // return undef;
    return eval { decode_json($raw) };
}

my sub read_modes {
    my $m = {};
    return $m if !-f $GUESTS_CFG;
    for my $l (split(/\n/, file_get_contents($GUESTS_CFG))) {
        $m->{$1} = $2 if $l =~ m/^\s*(\d+)\s*:\s*(auto|vsock|push|off)\s*$/;
    }
    return $m;
}

my sub write_modes {
    my ($m) = @_;
    my $data = "# pve-identity per-guest mode (default: auto)\n";
    $data .= "$_: $m->{$_}\n" for sort { $a <=> $b } keys %$m;
    mkdir $REG;
    file_set_contents($GUESTS_CFG, $data);
}

my sub guest_kind {
    my ($vmid) = @_;
    my $vl = PVE::Cluster::get_vmlist();
    my $e = $vl->{ids}->{$vmid} or return undef;
    return $e->{type};
}

my sub node_states {
    my $out = {};
    for my $node (@{PVE::Cluster::get_nodelist() // []}) {
        my $s = read_json("/etc/pve/nodes/$node/pve-identity.json") or next;
        $out->{$node} = $s;
    }
    return $out;
}

my sub can_see_guest {
    my ($rpcenv, $user, $g) = @_;
    return 1 if $rpcenv->check($user, "/vms/$g->{vmid}", ['VM.Audit'], 1);
    return 1 if defined($g->{pool}) && $rpcenv->check($user, "/pool/$g->{pool}", ['Pool.Audit'], 1);
    return 0;
}

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => { user => 'all' },
    parameters => { additionalProperties => 0, properties => {} },
    returns => { type => 'array', items => { type => 'object', properties => {} }, links => [{ rel => 'child', href => "{name}" }] },
    code => sub { return [{ name => 'status' }, { name => 'guests' }]; },
});

__PACKAGE__->register_method({
    name => 'status',
    path => 'status',
    method => 'GET',
    description => "Issuer, signing keys (public part only), audiences and daemon state per node.",
    permissions => { check => ['perm', '/', ['Sys.Audit']] },
    parameters => { additionalProperties => 0, properties => {} },
    returns => { type => 'object', properties => {} },
    code => sub {
        my $doc = read_json("$REG/issuers.d/pve.json") // {};
        my @aud;
        if (opendir(my $dh, "$REG/audiences.d")) {
            @aud = sort map { m/^([A-Za-z0-9._:-]+)\.json$/ ? $1 : () } readdir($dh);
            closedir($dh);
        }
        my $nodes = node_states();
        my $keys = [];
        my %thumb;
        for my $k (@{$doc->{jwks}->{keys} // []}) {
            push @$keys, { kid => $k->{kid}, alg => $k->{alg}, x5t => $k->{x5t} };
        }
        my ($any) = values %$nodes;
        for my $k (@$keys) {
            $k->{state} = ($any && ($any->{current_kid} // '') eq $k->{kid}) ? 'current'
                : ($any && ($any->{next_kid} // '') eq $k->{kid}) ? 'next' : 'previous';
        }
        return {
            enabled => (-f "$REG/issuers.d/pve.json") ? 1 : 0,
            issuer => $doc->{issuer},
            cluster => $doc->{cluster},
            sub_format => $doc->{sub_format},
            thumbprints => $doc->{thumbprints} // [],
            keys => $keys,
            audiences => \@aud,
            nodes => [map { { node => $_, issuer => $nodes->{$_}->{issuer} } } sort keys %$nodes],
        };
    },
});

__PACKAGE__->register_method({
    name => 'guests',
    path => 'guests',
    method => 'GET',
    description => "Guests with identity state. Only guests the caller may audit (VM.Audit on the guest or Pool.Audit on its pool) are listed.",
    permissions => { user => 'all' },
    parameters => { additionalProperties => 0, properties => {} },
    returns => { type => 'array', items => { type => 'object', properties => {} } },
    code => sub {
        my $rpcenv = PVE::RPCEnvironment::get();
        my $user = $rpcenv->get_user();
        my $modes = read_modes();
        my $res = [];
        my $nodes = node_states();
        for my $node (sort keys %$nodes) {
            for my $g (@{$nodes->{$node}->{guests} // []}) {
                next if !can_see_guest($rpcenv, $user, $g);
                $g->{mode} = $modes->{$g->{vmid}} // 'auto';
                $g->{channels} = join(',', @{$g->{channels} // []});
                $g->{pending_restart} = $g->{pending_restart} ? 1 : 0;
                $g->{running} = $g->{running} ? 1 : 0;
                push @$res, $g;
            }
        }
        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'get_guest',
    path => 'guests/{vmid}',
    method => 'GET',
    description => "Identity mode of a guest.",
    permissions => { check => ['perm', '/vms/{vmid}', ['VM.Audit']] },
    parameters => { additionalProperties => 0, properties => { vmid => get_standard_option('pve-vmid') } },
    returns => { type => 'object', properties => { mode => { type => 'string' } } },
    code => sub {
        my ($param) = @_;
        my $vmid = $param->{vmid};
        die "guest $vmid does not exist\n" if !guest_kind($vmid);
        return { vmid => $vmid, mode => read_modes()->{$vmid} // 'auto' };
    },
});

__PACKAGE__->register_method({
    name => 'set_guest',
    path => 'guests/{vmid}',
    method => 'PUT',
    protected => 1,
    description => "Set the identity mode of a guest (R24). Modes only reduce or reroute access.",
    permissions => { check => ['perm', '/vms/{vmid}', ['VM.Config.Options']] },
    parameters => {
        additionalProperties => 0,
        properties => {
            vmid => get_standard_option('pve-vmid'),
            mode => { type => 'string', enum => $MODES, description => "auto (default), vsock, push or off. Containers: auto or off." },
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;
        my ($vmid, $mode) = ($param->{vmid}, $param->{mode});
        my $kind = guest_kind($vmid) or die "guest $vmid does not exist\n";
        raise_param_exc({ mode => "containers support only 'auto' or 'off'" })
            if $kind eq 'lxc' && $mode ne 'auto' && $mode ne 'off';
        PVE::Cluster::cfs_lock_domain('pve-identity', 10, sub {
            my $m = read_modes();
            if ($mode eq 'auto') { delete $m->{$vmid} } else { $m->{$vmid} = $mode }
            write_modes($m);
        });
        die $@ if $@;
        return undef;
    },
});

1;
