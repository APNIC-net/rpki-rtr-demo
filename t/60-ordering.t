#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::RTR::PDU::IPv4Prefix;
use APNIC::RPKI::RTR::PDU::IPv6Prefix;
use APNIC::RPKI::RTR::PDU::ASPA;

use APNIC::RPKI::RTR::PDU::Utils qw(order_pdus
                                    pdus_are_ordered);

use Test::More tests => 20;

sub make_v4_add
{
    my ($addr, $length, $max_length, $asn) = @_;
    
    return APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
	version       => 1,
	flags         => 1,
	address       => $addr,
	prefix_length => $length,
	max_length    => $max_length,
	asn           => $asn,
    );
}

sub make_v4_del
{
    my ($addr, $length, $max_length, $asn) = @_;
    
    return APNIC::RPKI::RTR::PDU::IPv4Prefix->new(
	version       => 1,
	flags         => 0,
	address       => $addr,
	prefix_length => $length,
	max_length    => $max_length,
	asn           => $asn,
    );
}

sub make_aspa_add
{
    my ($customer_asn, $provider_asns) = @_;

    return APNIC::RPKI::RTR::PDU::ASPA->new(
	version       => 1,
	flags         => 1,
        customer_asn  => $customer_asn,
        provider_asns => $provider_asns
    );
}

sub make_v6_add
{
    my ($addr, $length, $max_length, $asn) = @_;
    
    return APNIC::RPKI::RTR::PDU::IPv6Prefix->new(
	version       => 1,
	flags         => 1,
	address       => $addr,
	prefix_length => $length,
	max_length    => $max_length,
	asn           => $asn,
    );
}

my @tests = (
    [ "Single PDU, no ordering difference", 
      [ make_v4_add("10.0.0.0", 24, 24, 1) ],
      [ make_v4_add("10.0.0.0", 24, 24, 1) ], ],
    [ "Larger address comes first",
      [ make_v4_add("10.0.0.0", 24, 24, 1),
        make_v4_add("11.0.0.0", 24, 24, 1) ],
      [ make_v4_add("11.0.0.0", 24, 24, 1),
        make_v4_add("10.0.0.0", 24, 24, 1) ], ],
    [ "Larger max-length comes first",
      [ make_v4_add("10.0.0.0", 24, 24, 1),
        make_v4_add("10.0.0.0", 24, 25, 1) ],
      [ make_v4_add("10.0.0.0", 24, 25, 1),
        make_v4_add("10.0.0.0", 24, 24, 1) ], ],
    [ "Larger prefix length comes first",
      [ make_v4_add("10.0.0.0", 24, 24, 1),
        make_v4_add("10.0.0.0", 25, 25, 1) ],
      [ make_v4_add("10.0.0.0", 25, 25, 1),
        make_v4_add("10.0.0.0", 24, 24, 1) ], ],
    [ "AS0 comes last",
      [ make_v4_add("10.0.0.0", 24, 24, 1),
        make_v4_add("10.0.0.0", 24, 24, 0) ],
      [ make_v4_add("10.0.0.0", 24, 24, 1),
        make_v4_add("10.0.0.0", 24, 24, 0) ], ],
    [ "Withdrawal comes last",
      [ make_v4_del("11.0.0.0", 24, 24, 1),
        make_v4_add("10.0.0.0", 24, 24, 1) ],
      [ make_v4_add("10.0.0.0", 24, 24, 1),
        make_v4_del("11.0.0.0", 24, 24, 1) ], ],
    [ "Larger address comes last with withdrawal",
      [ make_v4_del("11.0.0.0", 24, 24, 1),
        make_v4_del("10.0.0.0", 24, 24, 1) ],
      [ make_v4_del("10.0.0.0", 24, 24, 1),
        make_v4_del("11.0.0.0", 24, 24, 1) ], ],
    [ "Smaller PDU type comes first",
      [ make_aspa_add(1, [2, 3, 4]),
        make_v4_del("11.0.0.0", 24, 24, 1), ],
      [ make_v4_del("11.0.0.0", 24, 24, 1),
        make_aspa_add(1, [2, 3, 4]) ] ],
    [ "IPv4 comes first",
      [ make_v6_add("::", 24, 24, 1),
        make_v4_add("11.0.0.0", 24, 24, 1) ],
      [ make_v4_add("11.0.0.0", 24, 24, 1),
        make_v6_add("::", 24, 24, 1) ], ],
    [ "ASNs are ordered",
      [ make_v4_add("10.0.0.0", 24, 24, 2),
        make_v4_add("11.0.0.0", 24, 24, 1) ],
      [ make_v4_add("11.0.0.0", 24, 24, 1),
        make_v4_add("10.0.0.0", 24, 24, 2) ], ],
);

for my $test (@tests) {
    my ($str, $input_ref, $expected_output_ref) = @{$test};
    my @input = @{$input_ref};
    my @expected_output = @{$expected_output_ref};
    my @output = order_pdus(@input);

    my $output_json =
        join "\n", map { $_->serialise_json() }
            @output;
    my $expected_output_json =
        join "\n", map { $_->serialise_json() }
            @expected_output;
    is($output_json, $expected_output_json,
        "$str: got expected output");

    ok(pdus_are_ordered(@output),
        "$str: PDUs are ordered");
}

1;
