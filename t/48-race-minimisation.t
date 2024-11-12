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

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my $pdu =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '1.0.0.0',
            prefix_length => 24,
            max_length    => 24
        );
    $changeset->add_pdu($pdu);
    $mnt->apply_changeset($changeset);

    my $changeset2 = APNIC::RPKI::RTR::Changeset->new();
    my $pdu2 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '2.0.0.0',
            prefix_length => 32,
            max_length    => 32
        );
    $changeset2->add_pdu($pdu2);
    $mnt->apply_changeset($changeset2);

    my $changeset3 = APNIC::RPKI::RTR::Changeset->new();
    my $pdu3 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 4608,
            address       => '1.0.0.0',
            prefix_length => 23,
            max_length    => 23
        );
    $changeset3->add_pdu($pdu3);
    $mnt->apply_changeset($changeset3);

    my $changeset4 = APNIC::RPKI::RTR::Changeset->new();
    my $pdu4 =
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            asn           => 0,
            address       => '1.0.0.0',
            prefix_length => 23,
            max_length    => 23
        );
    $changeset4->add_pdu($pdu4);
    $mnt->apply_changeset($changeset4);

    my @pdus;
    $client->{'pdu_cb'} = sub { push @pdus, $_[0] };
    eval { $client->reset() };
    my $error = $@;
    ok((not $error), 'Reset client successfully');
    # For end of data.
    pop @pdus;

    my @data =
        map  { $_->address().'/'.$_->prefix_length().
               '-'.$_->max_length().':'.$_->asn() }
        grep {    ($_->type() == PDU_IPV4_PREFIX())
               or ($_->type() == PDU_IPV6_PREFIX()) }
            @pdus;
    is_deeply(
        \@data,
        [ '2.0.0.0/32-32:4608',
          '1.0.0.0/24-24:4608',
          '1.0.0.0/23-23:4608',
          '1.0.0.0/23-23:0' ],
        'Got PDUs in expected order'
    );

    $client->exit_server();
}

END {
    if ($pid) {
        kill('TERM', $pid);
    }
}

1;
