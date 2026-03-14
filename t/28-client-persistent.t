#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;

use File::Slurp qw(read_file);
use File::Temp qw(tempdir);
use JSON::XS qw(decode_json);
use Net::EmptyPort qw(empty_port);

use Test::More tests => 2;

my @pids;

{
    # Set up the server and clients.

    my $data_dir = tempdir(CLEANUP => 1); 
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port = empty_port();
    my $server =
        APNIC::RPKI::RTR::Server->new(
            server   => '127.0.0.1',
            port     => $port,
            data_dir => $data_dir,
        );

    if (my $ppid = fork()) {
        push @pids, $ppid;
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
            max_length    => 32,
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);

    my $state_path_ft = File::Temp->new();
    my $state_path = $state_path_ft->filename();
    my $client =
        APNIC::RPKI::RTR::Client->new(
            server     => '127.0.0.1',
            port       => $port,
            state_path => $state_path,
        );
    
    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        $client->reset(undef, 1);
        exit(0);
    }

    my $state_path2_ft = File::Temp->new();
    my $state_path2 = $state_path2_ft->filename();
    my $client2 =
        APNIC::RPKI::RTR::Client->new(
            server     => '127.0.0.1',
            port       => $port,
            state_path => $state_path2,
        );
    
    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        $client2->reset(undef, 1);
        exit(0);
    }
    sleep(1);
       
    # The clients are trying to reset, so they should get the 1.0.0.0/24
    # prefix by way of a serial notify notification.

    for my $sp ($state_path, $state_path2) {
        my $state_data = read_file($state_path);
        $state_data = decode_json($state_data);
        $state_data = decode_json($state_data->{'state'});
        ok((exists $state_data->{'vrps'}
                              ->{'4608'}->{'1.0.0.0'}->{'24'}),
            'Clients have first VRP');
    }

    for my $pid (@pids) {
        kill('TERM', $pid);
    }
}

END {
    for my $pid (@pids) {
        kill('TERM', $pid);
    }
}

1;
