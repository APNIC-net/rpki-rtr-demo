package APNIC::RPKI::Validator::ROA;

use strict;
use warnings;

use APNIC::RPKI::RTR::Utils qw(dprint);

use Net::IP::XS qw($IP_B_IN_A_OVERLAP);
use Data::Dumper;

use constant {
    ROV_INVALID => 0,
    ROV_UNKNOWN => 1,
    ROV_VALID   => 2,
};

use base 'Exporter';

our @EXPORT_OK = qw(ROV_INVALID ROV_UNKNOWN ROV_VALID);

sub validate
{
    my ($state, $asn, $prefix) = @_;

    my $route_prefix = new Net::IP::XS($prefix)
        or die (Net::IP::XS::Error());

    my $result = ROV_UNKNOWN;
    my $vrps = $state->{vrps};

    my $route_with_covering_prefix;
    foreach my $vrp_asn (sort keys %{$vrps}) {
        my %vrp_asn_values = %{$vrps->{$vrp_asn}};
        foreach my $vrp_address (sort keys %vrp_asn_values) {
            my $vrp_ip = new Net::IP::XS($vrp_address)
                or die (Net::IP::XS::Error());
            # if the vrp's starting ip is greater, it won't be a covering
            # range.
            next if $vrp_ip->intip > $route_prefix->intip;

            my %vrp_address_value = %{$vrp_asn_values{$vrp_address}};
            foreach my $prefix_len (sort keys %vrp_address_value) {
                my $vrp_prefix = new Net::IP::XS("$vrp_address/$prefix_len")
                    or die (Net::IP::XS::Error());
                # if the vrp's last ip is lesser, it won't be a covering range.
                next if $vrp_prefix->last_int < $route_prefix->last_int;

                $route_with_covering_prefix =
                    "AS$vrp_asn " . $vrp_prefix->prefix;
                dprint("route-origin-validation: Found vrp " .
                    "($route_with_covering_prefix) with covering prefix.");

                my %prefix_len_value = %{$vrp_address_value{$prefix_len}};
                foreach my $max_len (sort keys %prefix_len_value) {
                    if ($route_prefix->prefixlen <= $max_len
                            and $vrp_asn != 0
                            and $vrp_asn == $asn) {
                        dprint("route-origin-validation: Found valid rov" .
                            "($route_with_covering_prefix-$max_len).");
                        return ROV_VALID;
                    } else {
                        $route_with_covering_prefix .= "-$max_len";
                    }
                }
            }
        }
    }

    # A covering prefix of a non-matching ASN would be 'INVALID'.
    if ($route_with_covering_prefix) {
        dprint("route-origin-validation: Found invalid rov " .
            "($route_with_covering_prefix).");
        $result = ROV_INVALID;
    }

    dprint("route-origin-validation: No vrp with covering prefix.");
    return $result;
}

1;