#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::Constants qw(ERR_CORRUPT_DATA);

use File::Slurp qw(read_file write_file);
use File::Temp qw(tempdir);
use JSON::XS qw(decode_json);
use Net::EmptyPort qw(empty_port);

use Test::More tests => 4;

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
            server         => '127.0.0.1',
            port           => $port,
            data_dir       => $data_dir,
            retry_interval => 5,
        );

    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        for (;;) {
            my $server =
                APNIC::RPKI::RTR::Server->new(
                    server         => '127.0.0.1',
                    port           => $port,
                    data_dir       => $data_dir,
                    retry_interval => 5
                );
            $server->run();
            diag("Server exited, sleeping for 2s before restarting...");
            sleep(2);
        }
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

    my $corrupt_data_ft = File::Temp->new();
    my $corrupt_data_fn = $corrupt_data_ft->filename();
    
    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        for (;;) {
            eval { $client->reset(undef, 1); };
            if (my $error = $@) {
                my $error_pdu = $client->{'error_pdu'};
                if ($error_pdu->error_code() == ERR_CORRUPT_DATA()) {
                    # This will happen when the server restarts, so
                    # just try again in this case.
                    write_file($corrupt_data_fn, "yes");
                    next;
                } else {
                    die $error;
                }
            }
        }
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

    my $corrupt_data2_ft = File::Temp->new();
    my $corrupt_data2_fn = $corrupt_data2_ft->filename();
    
    if (my $ppid = fork()) {
        push @pids, $ppid;
    } else {
        for (;;) {
            eval { $client2->reset(undef, 1); };
            if (my $error = $@) {
                my $error_pdu = $client2->{'error_pdu'};
                if ($error_pdu->error_code() == ERR_CORRUPT_DATA()) {
                    # This will happen when the server restarts, so
                    # just try again in this case.
                    write_file($corrupt_data2_fn, "yes");
                    next;
                } else {
                    die $error;
                }
            }
        }
        exit(0);
    }
    sleep(1);

    # Send the restart signal to the server.  Because the clients are
    # operating persistently, they should receive the cache restart
    # PDU, block until the retry interval is reached, and then reset
    # on realising that the session ID has changed.

    kill('HUP', $pids[0]);
    sleep(7);

    for my $sp ($state_path, $state_path2) {
        my $state_data = read_file($state_path);
        $state_data = decode_json($state_data);
        $state_data = decode_json($state_data->{'state'});
        ok((exists $state_data->{'vrps'}
                              ->{'4608'}->{'1.0.0.0'}->{'24'}),
            'Clients have first VRP');
    }
    my ($cd_line) = read_file($corrupt_data_ft);
    chomp $cd_line;
    is($cd_line, "yes", "Got corrupt data error for first client");
    my ($cd2_line) = read_file($corrupt_data2_ft);
    chomp $cd2_line;
    is($cd2_line, "yes", "Got corrupt data error for second client");

    for my $pid (@pids) {
        kill('KILL', $pid);
    }
}

END {
    for my $pid (@pids) {
        kill('KILL', $pid);
    }
}

1;
