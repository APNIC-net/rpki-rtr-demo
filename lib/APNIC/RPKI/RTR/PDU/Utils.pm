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
use APNIC::RPKI::RTR::PDU::Exit;
use APNIC::RPKI::RTR::Utils qw(dprint
                               recv_all);

use IO::Socket::SSL;
use JSON::XS qw(decode_json);

my $SENTINEL_ASN = 1 << 32;

use base qw(Exporter);

our @EXPORT_OK = qw(parse_pdu
                    order_pdus
                    pdus_are_ordered
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
    PDU_EXIT()           => 'Exit',
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
    if ($buf and $buf =~ /-1/) {
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

    # The ordering algorithm here is slightly different from that in
    # -21:
    #
    #  - Addition IP PDUs are ordered from larger address to smaller
    #    address, rather than smaller to larger, because the ordering
    #    will lead to incorrect results otherwise.
    #  - Addition IP PDU max length ordering (larger to smaller)
    #    occurs before prefix length ordering, because the ordering
    #    will lead to incorrect results otherwise.
    #  - The document is not clear on how withdrawal is supposed to
    #    be handled.  The algorithm here simply reverses whatever is
    #    used for addition.  One issue with this is that withdrawal
    #    PDUs will have ASNs in descending order, but that seems like
    #    a reasonable tradeoff for securing the reversal behaviour.

    my @ip_pdus =
        map  { $_->[0] }
            # Order from larger address to smaller address, so that
            # subprefixes come first, and so that addresses are
            # processed as close together as possible.
        sort { ($b->[1] <=> $a->[1])
            # Order from larger max length to smaller max length, so
            # that a PDU with a smaller max length doesn't
            # inadvertently invalidate a route with a larger max
            # length.
                || ($b->[0]->max_length()
                    <=> $a->[0]->max_length())
            # Order from larger prefix length to smaller prefix
            # length, for similar reasons to the previous part.
                || ($b->[0]->prefix_length()
                    <=> $a->[0]->prefix_length())
            # Put AS0 PDUs last, but otherwise order ascending.
                || (($a->[0]->asn() || $SENTINEL_ASN)
                    <=> ($b->[0]->asn() || $SENTINEL_ASN)) }
        map  { [ $_, $_->address_as_number() ] }
        grep { ($_->type() == PDU_IPV4_PREFIX()
             or $_->type() == PDU_IPV6_PREFIX()) }
            @pdus;

    my @add_ipv4_pdus =
        grep { $_->flags() == 1
                and $_->type() == PDU_IPV4_PREFIX() }
            @ip_pdus;
    
    # The ordering used for additions should be reversed for removals.
    my @remove_ipv4_pdus =
        reverse
        grep { $_->flags() == 0
                and $_->type() == PDU_IPV4_PREFIX() }
            @ip_pdus;

    my @add_ipv6_pdus =
        grep { $_->flags() == 1
                and $_->type() == PDU_IPV6_PREFIX() }
            @ip_pdus;
    
    my @remove_ipv6_pdus =
        reverse
        grep { $_->flags() == 0
                and $_->type() == PDU_IPV6_PREFIX() }
            @ip_pdus;

    my @router_key_pdus =
        sort { ($a->asn() <=> $b->asn())
                || ($a->spki() cmp $b->spki()) }
        grep { $_->type() == PDU_ROUTER_KEY() }
            @pdus;

    my @aspa_pdus =
        sort { $a->customer_asn() <=> $b->customer_asn() }
        grep { $_->type() == PDU_ASPA() }
            @pdus;

    my @other_pdus =
        grep { $_->type() != PDU_IPV4_PREFIX()
                and $_->type() != PDU_IPV6_PREFIX()
                and $_->type() != PDU_ROUTER_KEY()
                and $_->type() != PDU_ASPA() }
            @pdus;
    if (@other_pdus) {
        die "Unhandled PDU types found in order_pdus";
    }

    return (@add_ipv4_pdus,
            @remove_ipv4_pdus,
            @add_ipv6_pdus,
            @remove_ipv6_pdus,
            @router_key_pdus,
            @aspa_pdus);
}

sub pdus_are_ordered
{
    my (@pdus) = @_;

    my $last_pdu = shift @pdus;
    my $msg = "PDU ordering incorrect";

    for my $pdu (@pdus) {
        my $last_pdu_type = $last_pdu->type();
        my $type = $pdu->type();
        if ($type < $last_pdu_type) {
            my $tm = type_to_module($type);
            my $ctm = type_to_module($last_pdu_type);
            dprint("$msg: $tm found after $ctm");
            return 0;
        }
        if ((($type == PDU_IPV4_PREFIX())
                and ($last_pdu_type == PDU_IPV4_PREFIX()))
                or (($type == PDU_IPV6_PREFIX())
                        and ($last_pdu_type == PDU_IPV6_PREFIX()))) {
            if ($pdu->flags() == 1) {
                if ($last_pdu->flags() == 0) {
                    dprint("$msg: addition found after withdrawal");
                    return 0;
                } elsif ($pdu->address_as_number()
                            > $last_pdu->address_as_number()) {
                    dprint("$msg: addition of larger address");
                    return 0;
                } elsif ($pdu->prefix_length()
                            > $last_pdu->prefix_length()) {
                    dprint("$msg: addition of larger prefix length");
                    return 0;
                } elsif ($pdu->max_length()
                            > $last_pdu->max_length()) {
                    dprint("$msg: addition of larger max length");
                    return 0;
                } elsif (($pdu->asn() || $SENTINEL_ASN)
                            < ($last_pdu->asn() || $SENTINEL_ASN)) {
                    dprint("$msg: addition with incorrect ASN ordering");
                    return 0;
                }
            } elsif ($pdu->address_as_number()
                        < $last_pdu->address_as_number()) {
                dprint("$msg: withdrawal of smaller address");
                return 0;
            } elsif ($pdu->prefix_length()
                        < $last_pdu->prefix_length()) {
                dprint("$msg: withdrawal of smaller prefix length");
                return 0;
            } elsif ($pdu->max_length()
                        < $last_pdu->max_length()) {
                dprint("$msg: withdrawal of smaller max length");
                return 0;
            } elsif (($pdu->asn() || $SENTINEL_ASN)
                        > ($last_pdu->asn() || $SENTINEL_ASN)) {
                dprint("$msg: withdrawal with incorrect ASN ordering");
                return 0;
            }
        }
        $last_pdu = $pdu;
    }

    return 1;
}

sub deserialise_json
{
    my ($data) = @_;

    my $decoded_data = decode_json($data);
    my $module = type_to_module($decoded_data->{'type'});
    return $module->deserialise_json($data);
}

1;
