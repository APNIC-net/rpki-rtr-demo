package APNIC::RPKI::RTR::PDU;

use warnings;
use strict;

sub new
{
    die "Abstract";
}

sub type
{
    die "Abstract";
}

sub is_ip_type
{
    die "Abstract";
}

sub overlaps
{
    die "Abstract";
}

sub serialise_binary
{
    die "Abstract";
}

sub deserialise_binary
{
    die "Abstract";
}

sub serialise_json
{
    die "Abstract";
}

sub deserialise_json
{
    die "Abstract";
}

sub is_reversal_of
{
    die "Abstract";
}

sub supported_in_version
{
    die "Abstract";
}

1;
