#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Server;
use APNIC::RPKI::RTR::Server::Maintainer;
use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::PDU::Utils qw(parse_pdu);

use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);

use Test::More tests => 4;

my $pid;

{
    # Set up the server and the client.

    my $data_dir = tempdir(CLEANUP => 1);
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );
    my $port = empty_port();
    # This interval configuration would not be permitted in practice,
    # and is only being used here for testing.
    my $server =
        APNIC::RPKI::RTR::Server->new(
            server           => '127.0.0.1',
            port             => $port,
            data_dir         => $data_dir,
            refresh_interval => 3600,
            retry_interval   => 3600,
            expire_interval  => 1,
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

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my %defaults = (
        version       => 1,
        flags         => 1,
        asn           => 4608,
        prefix_length => 24,
        max_length    => 24
    );
    my $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            %defaults,
            address => '1.0.0.0',
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset, 4294967292);

    eval { $client->reset() };
    my $error = $@;
    ok((not $error), 'Reset client successfully');

    sleep(2);
    my @pdus;
    $client->{'pdu_cb'} = sub { push @pdus, $_[0] };
    eval { $client->refresh() };
    $error = $@;
    ok((not $error), 'Refreshed client successfully');

    my @pdu_types = map { $_->type() } @pdus;
    is_deeply(\@pdu_types,
              [ PDU_CACHE_RESPONSE(),
                PDU_IPV4_PREFIX(),
                PDU_END_OF_DATA() ],
              'Reset on expiry interval being reached');

    sleep(2);
    my $state = $client->state();
    is($state, undef, 'State not available on expiry '.
                      'interval being reached');

    $client->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
