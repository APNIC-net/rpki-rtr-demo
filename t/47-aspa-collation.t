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

use File::Slurp qw(read_file);
use File::Temp qw(tempdir);
use JSON::XS qw(decode_json);

use Test::More tests => 1;

{
    my $data_dir = tempdir(CLEANUP => 1);
    my $mnt =
        APNIC::RPKI::RTR::Server::Maintainer->new(
            data_dir => $data_dir
        );

    my $changeset = APNIC::RPKI::RTR::Changeset->new();
    my $pdu =
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            customer_asn  => 4608,
            provider_asns => [1]
        );
    $changeset->add_pdu($pdu);
    my $pdu2 =
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            customer_asn  => 4608,
            provider_asns => [2]
        );
    $changeset->add_pdu($pdu2);
    $mnt->apply_changeset($changeset);

    my $mnt_data = read_file("$data_dir/snapshot.json");
    my $decoded = decode_json($mnt_data);
    is_deeply($decoded->{'aspas'}->{'4608'},
              [1, 2],
              'ASPAs collated');
}

1;
