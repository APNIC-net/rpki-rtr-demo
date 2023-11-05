package APNIC::RPKI::RTR::PDU::Utils;

use warnings;
use strict;

use APNIC::RPKI::RTR::PDU::SerialNotify;
use APNIC::RPKI::RTR::PDU::SerialQuery;
use APNIC::RPKI::RTR::PDU::ResetQuery;
use APNIC::RPKI::RTR::PDU::CacheResponse;
use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::PDU::IPv6Prefix;
use APNIC::RPKI::RTR::PDU::EndOfData;
use APNIC::RPKI::RTR::PDU::CacheReset;
use APNIC::RPKI::RTR::PDU::RouterKey;
use APNIC::RPKI::RTR::PDU::ErrorReport;
use APNIC::RPKI::RTR::PDU::ASPA;
use APNIC::RPKI::RTR::Utils qw(recv_all);

use JSON::XS qw(decode_json);

use base qw(Exporter);

our @EXPORT_OK = qw(parse_pdu);

my %TYPE_TO_MODULE = (
    0  => 'SerialNotify',
    1  => 'SerialQuery',
    2  => 'ResetQuery',
    3  => 'CacheResponse',
    4  => 'IPv4Prefix',
    6  => 'IPv6Prefix',
    7  => 'EndOfData',
    8  => 'CacheReset',
    9  => 'RouterKey',
    10 => 'ErrorReport',
    11 => 'ASPA',
);

sub type_to_module
{
    my ($type) = @_;

    my $module_name = exists $TYPE_TO_MODULE{$type};
    if (not $module_name) {
        die "Type '$type' does not map to a PDU module.";
    }
    return "APNIC::RPKI::RTR::PDU::".$TYPE_TO_MODULE{$type};
}

sub parse_pdu
{
    my ($socket) = @_;

    my $buf = recv_all($socket, 8);
    my ($version, $type, $session_id, $length) =
        unpack("CCnN", $buf);
    if (not (($version == 1) or ($version == 2))) {
        die "Unsupported version '$version' ($type, $session_id, $length)";
    }

    my $module = type_to_module($type);
    return
        $module->deserialise_binary(
            $version, $session_id, $length, $socket
        );
}

sub deserialise_json
{
    my ($data) = @_;

    my $decoded_data = decode_json($data);
    my $module = type_to_module($decoded_data->{'type'});
    return $module->deserialise_json($data);
}

1;
