package APNIC::RPKI::RTR::PDU::Utils;

use warnings;
use strict;

use APNIC::RPKI::RTR::Constants;
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

our @EXPORT_OK = qw(parse_pdu
                    order_pdus
                    error_type_to_string);

my %TYPE_TO_MODULE = (
    PDU_SERIAL_NOTIFY()  => 'SerialNotify',
    PDU_SERIAL_QUERY()   => 'SerialQuery',
    PDU_RESET_QUERY()    => 'ResetQuery',
    PDU_CACHE_RESPONSE() => 'CacheResponse',
    PDU_IPV4_PREFIX()    => 'IPv4Prefix',
    PDU_IPV6_PREFIX()    => 'IPv6Prefix',
    PDU_END_OF_DATA()    => 'EndOfData',
    PDU_CACHE_RESET()    => 'CacheReset',
    PDU_ROUTER_KEY()     => 'RouterKey',
    PDU_ERROR_REPORT()   => 'ErrorReport',
    PDU_ASPA()           => 'ASPA',
);

my %ERROR_TYPE_TO_STRING = (
    ERR_CORRUPT_DATA()                    => 'Corrupt Data',
    ERR_INTERNAL_ERROR()                  => 'Internal Error',
    ERR_NO_DATA()                         => 'No Data',
    ERR_INVALID_REQUEST()                 => 'Invalid Request',
    ERR_UNSUPPORTED_VERSION()             => 'Unsupported Version',
    ERR_UNSUPPORTED_PDU_TYPE()            => 'Unsuppported PDU Type',
    ERR_WITHDRAWAL_OF_UNKNOWN_RECORD()    => 'Withdrawal of Unknown Record',
    ERR_DUPLICATE_ANNOUNCEMENT_RECEIVED() => 'Duplicate Announcement Received',
    ERR_UNEXPECTED_PROTOCOL_VERSION()     => 'Unexpected Protocol Version',
    ERR_ASPA_PROVIDER_LIST_ERROR()        => 'ASPA Provider List Error',
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

sub error_type_to_string
{
    my ($type) = @_;

    my $string = exists $ERROR_TYPE_TO_STRING{$type};
    if (not $string) {
        die "Error type '$type' does not map to a string.";
    }
    return $ERROR_TYPE_TO_STRING{$type};
}

sub parse_pdu
{
    my ($socket) = @_;

    my $buf = recv_all($socket, 8);
    if ($buf and $buf =~ "-1") {
        return;
    }
    my ($version, $type, $session_id, $length) =
        unpack("CCnN", $buf);
    if (not (($version >= 0) and ($version <= 2))) {
        die "Unsupported version '$version' ($type, $session_id, $length)";
    }

    my $module = type_to_module($type);
    return
        $module->deserialise_binary(
            $version, $session_id, $length, $socket
        );
}

sub order_pdus
{
    my (@pdus) = @_;

    my @ip_pdus =
        map  { $_->[0] }
        sort { ($a->[0]->type() <=> $b->[0]->type())
                || ($a->[1] <=> $b->[1])
                || ($b->[0]->prefix_length()
                    <=> $a->[0]->prefix_length())
                || ($b->[0]->max_length()
                    <=> $a->[0]->max_length()) }
        map  { [ $_, $_->address_as_number() ] }
        grep { $_->type() == PDU_IPV4_PREFIX()
            or $_->type() == PDU_IPV6_PREFIX() }
            @pdus;

    my @non_ip_pdus =
        grep { $_->type() != PDU_IPV4_PREFIX()
           and $_->type() != PDU_IPV6_PREFIX() }
            @pdus;

    return (@ip_pdus, @non_ip_pdus);
}

sub deserialise_json
{
    my ($data) = @_;

    my $decoded_data = decode_json($data);
    my $module = type_to_module($decoded_data->{'type'});
    return $module->deserialise_json($data);
}

1;
