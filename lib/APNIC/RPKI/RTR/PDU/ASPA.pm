package APNIC::RPKI::RTR::PDU::ASPA;

use warnings;
use strict;

use JSON::XS qw(decode_json);

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Utils qw(inet_pton
                               inet_ntop
                               dprint
                               recv_all
                               get_zero
                               encode_json_rtr);

use base qw(APNIC::RPKI::RTR::PDU);

sub new
{
    my $class = shift;
    my %args = @_;

    if (not $args{'customer_asn'}) {
        die "Expected customer ASN";
    } 
    if (not $args{'provider_asns'}) {
        die "Expected provider ASNs";
    }
    if (not defined $args{'flags'}) {
        die "Expected flags";
    }

    my $self = {
        version       => $args{'version'},
        flags         => $args{'flags'},
        customer_asn  => $args{'customer_asn'},
        provider_asns => $args{'provider_asns'},
    };
    bless $self, $class;
    return $self;
}

sub type
{
    return PDU_ASPA();
}

sub type_str
{
    return 'ASPA';
}

sub version
{
    my ($self) = @_;

    return $self->{'version'};
}

sub flags
{
    my ($self) = @_;

    return $self->{'flags'};
}

sub afi_flags
{
    my ($self) = @_;

    return $self->{'afi_flags'};
}

sub customer_asn
{
    my ($self) = @_;

    return $self->{'customer_asn'};
}

sub provider_asns
{
    my ($self) = @_;

    return $self->{'provider_asns'};
}

sub serialise_binary
{
    my ($self) = @_;

    my @provider_asns = @{$self->provider_asns()};
    my $flags = $self->flags();
    if ($flags == 0) {
        # Provider ASNs are omitted on withdrawal.
        @provider_asns = ();
    }
    my $pc = scalar @provider_asns;

    return pack("CCCCNNN$pc",
                $self->version(),
                $self->type(),
                $self->flags(),
                get_zero(8),
                12 + (4 * $pc),
                $self->customer_asn(),
                @{$self->provider_asns()});
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    my $buf = recv_all($socket, 4);
    my ($customer_asn) = unpack("N", $buf);
    my $provider_bytes = $length - 12;
    $buf = recv_all($socket, $provider_bytes);
    my $provider_count = $provider_bytes / 4;
    my @provider_asns = unpack("N$provider_count", $buf);
    my $flags = ($session_id >> 8) & 0xFF;

    return
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => $version,
            flags         => $flags,
            customer_asn  => $customer_asn,
            provider_asns => \@provider_asns,
        );
}

sub serialise_json
{
    my ($self) = @_;

    return encode_json_rtr({%{$self}, type => $self->type()});
}

sub deserialise_json
{
    my ($class, $data) = @_;

    my $self = decode_json($data);
    bless $self, $class;
    return $self;
}

sub is_reversal_of
{
    my ($self, $other) = @_;

    if ($self->type() != $other->type()) {
        return;
    }

    return (($self->type() == $other->type())
                and ($self->customer_asn() == $other->customer_asn())
                and ($self->flags() == 0)
                and ($other->flags() == 1));
}

sub equals
{
    my ($self, $other) = @_;

    if ($self->type() != $other->type()) {
        return;
    }

    my @self_provider_asns  = sort @{$self->provider_asns()};
    my @other_provider_asns = sort @{$other->provider_asns()};
    if (@self_provider_asns != @other_provider_asns) {
        return;
    }
    for (my $i = 0; $i < @self_provider_asns; $i++) {
        if ($self_provider_asns[$i] != $other_provider_asns[$i]) {
            return;
        }
    }

    return (($self->customer_asn() == $other->customer_asn())
                and ($self->flags() == $other->flags()));
}

sub supported_in_version
{
    my ($self, $version) = @_;

    return ($version == 2);
}

1;
