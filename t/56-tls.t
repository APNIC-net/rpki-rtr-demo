#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Slurp qw(read_file write_file);
use File::Temp qw(tempdir);

use Test::More tests => 3;

my $pid;

{
    my $data_dir = tempdir(CLEANUP => 1); 
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;

    my $ca_root_dir = tempdir();
    $ENV{'CAROOT'} = $ca_root_dir;
    # Limit to 'nss' here, to avoid needing root access for system CA
    # store updates.
    $ENV{'TRUST_STORES'} = 'nss';
    my $res = system("mkcert -install");
    if ($res != 0) {
        die "Unable to create new CA certificate";
    }
    my $ca_path_ft = File::Temp->new();
    my $ca_path_fn = $ca_path_ft->filename();
    my $ca_file = read_file("$ca_root_dir/rootCA.pem");
    write_file($ca_path_fn, $ca_file);
    # Remove from local trust stores, to ensure that later
    # configuration works as intended.
    $res = system("mkcert -uninstall");
    if ($res != 0) {
        die "Unable to remove CA certificate from local trust stores";
    }
    my $cert_path_ft = File::Temp->new();
    my $key_path_ft  = File::Temp->new();
    my $cert_path_fn = $cert_path_ft->filename();
    my $key_path_fn  = $key_path_ft->filename();
    $res = system("mkcert ".
                  "-cert-file $cert_path_fn ".
                  "-key-file $key_path_fn ".
                  "127.0.0.1");
    if ($res != 0) {
        die "Unable to create new server certificate";
    }

    my $server =
        APNIC::RPKI::RTR::Server->new(
            server    => '127.0.0.1',
            port      => $port,
            data_dir  => $data_dir,
            cert_file => $cert_path_fn,
            key_file  => $key_path_fn,
        );

    if (my $ppid = fork()) {
        $pid = $ppid;
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '1.0.0.0',
            prefix_length => 24,
            max_length    => 32
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);

    # Can't connect to TLS server with non-TLS client.

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server      => '127.0.0.1',
            port        => $port,
            timeout     => 1,
            tls         => 0,
        );

    eval { $client->reset() };
    my $error = $@;
    ok($error, 'Cannot connect to TLS server with non-TLS client');
    like($error, qr/Connection reset by peer/,
        'Got expected error message');

    # Can connect to TLS server with TLS client (quelle surprise).

    $client =
        APNIC::RPKI::RTR::Client->new(
            server  => '127.0.0.1',
            port    => $port,
            timeout => 1,
            tls     => 1,
            ca_file => $ca_path_fn,
        );

    eval { $client->reset() };
    $error = $@;
    ok((not $error), 'Can connect to TLS server with TLS client');

    $client->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
