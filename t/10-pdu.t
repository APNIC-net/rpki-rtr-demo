#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::PDU::Utils qw(parse_pdu);
use APNIC::RPKI::RTR::PDU::IPv4Prefix;

use Scalar::Util qw(blessed);

use lib 't/lib';
use MockSocket;

use Test::More tests => 98;

{
    my @pdus = (
        APNIC::RPKI::RTR::PDU::SerialNotify->new(
            version       => 1,
            session_id    => 1,
            serial_number => 1,
        ),
        APNIC::RPKI::RTR::PDU::SerialQuery->new(
            version       => 1,
            session_id    => 1,
            serial_number => 1,
        ),
        APNIC::RPKI::RTR::PDU::ResetQuery->new(
            version       => 1,
        ),
        APNIC::RPKI::RTR::PDU::CacheResponse->new(
            version    => 1,
            session_id => 1,
        ),
        APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
            version       => 1,
            flags         => 1,
            address       => '1.0.0.0',
            prefix_length => 24,
            max_length    => 32,
            asn           => 4608
        ),
        APNIC::RPKI::RTR::PDU::IPv6Prefix->new(
            version       => 1,
            flags         => 1,
            address       => '2001:1234::',
            prefix_length => 24,
            max_length    => 32,
            asn           => 4608
        ),
        APNIC::RPKI::RTR::PDU::EndOfData->new(
            version          => 1,
	    session_id       => 1,
	    serial_number    => 1,
	    refresh_interval => 10,
	    retry_interval   => 20,
	    expire_interval  => 30,
        ),
        APNIC::RPKI::RTR::PDU::CacheReset->new(
            version => 1,
        ),
        APNIC::RPKI::RTR::PDU::RouterKey->new(
            version  => 1,
            flags    => 1,
            ski      => 1234,
            asn      => 4608,
            spki     => 'asdf',
        ),
        APNIC::RPKI::RTR::PDU::ErrorReport->new(
            version       => 1,
            error_code    => ERR_NO_DATA(),
        ),
        APNIC::RPKI::RTR::PDU::ErrorReport->new(
            version          => 1,
            error_code       => ERR_NO_DATA(),
            error_text       => 'asdfasdfasdf',
            encapsulated_pdu =>
                APNIC::RPKI::RTR::PDU::SerialQuery->new(
                    version       => 1,
                    session_id    => 1,
                    serial_number => 1,
                ),
        ),
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            afi_flags     => 3,
            customer_asn  => 4608,
            provider_asns => []
        ),
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => 2,
            flags         => 1,
            afi_flags     => 3,
            customer_asn  => 4608,
            provider_asns => [50, 60, 40]
        ),
        APNIC::RPKI::RTR::PDU::SubscribingData->new(
            version    => 2,
            data_types => [4, 6]
        ),
    );

    for my $pdu (@pdus) {
        my $module = blessed $pdu;
        ok($pdu, "Got new $module PDU");

        my $mock_socket = MockSocket->new($pdu->serialise_binary());

        my $new_pdu = parse_pdu($mock_socket);
        ok($new_pdu, "Deserialised $module PDU from existing PDU");
        ok($mock_socket->exhausted(), 'All data used');

        my $res = ok($pdu->equals($new_pdu),
                        'PDUs are equal');
        if (not $res) {
            diag "Failed equality test for '".$module->type_str()."'";
        }

        my $json = $pdu->serialise_json();
        ok($json, 'Got JSON serialisation of PDU');
        my $new_json_pdu =
            APNIC::RPKI::RTR::PDU::Utils::deserialise_json($json);
        ok($new_json_pdu, 'Deserialised JSON to PDU');
        ok($pdu->equals($new_json_pdu),
            'PDUs are equal (JSON serialisation)');
    }
}

1;
