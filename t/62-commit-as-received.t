#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::Validator::ROA;

use File::Temp qw(tempdir);

use Test::More tests => 2;

my $pid;

{
    # Set up the server and the client.

    my $data_dir = tempdir(CLEANUP => 1); 
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port =
        ($$ + int(rand(1024))) % (65535 - 1024) + 1024;
    my $server =
        APNIC::RPKI::RTR::Server->new(
            server   => '127.0.0.1',
            port     => $port,
            data_dir => $data_dir,
        );

    if (my $ppid = fork()) {
        $pid = $ppid;
    } else {
        $server->run();
        exit(0);
    }
    sleep(1);

    my $client =
        APNIC::RPKI::RTR::Client->new(
            server             => '127.0.0.1',
            port               => $port,
            supported_versions => [2],
        );

    # Add two IPv4 prefixes to the server, with one being
    # more-specific than the other.

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my $pdu1 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '1.0.0.0',
            prefix_length => 24,
            max_length    => 24,
        );
    $changeset->add_pdu($pdu1);
    my $pdu2 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '1.0.0.0',
            prefix_length => 25,
            max_length    => 25,
        );
    $changeset->add_pdu($pdu2);
    $mnt->apply_changeset($changeset);

    # Try to reset, after configuring the client to commit changesets
    # as they are received, and to validate a route on each commit.
    # Validation should succeed each time, due to ordering.

    $client->{'commit_as_received'} = 1;
    my @results;
    $client->{'post_commit_cb'} = sub {
        my $res =
            APNIC::RPKI::Validator::ROA::validate(
                $client->{'state'},
                "4608",
                "1.0.0.0/25"
            );
        push @results, $res;
    };

    eval { $client->reset() };
    my $error = $@;
    ok((not $error), 'Got successful response from server');
    if ($error) {
        use Data::Dumper;
        diag Dumper($error);
    }

    is_deeply(\@results, [2, 2, 2],
              'Got expected validation result');

    $client->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
