package APNIC::RPKI::RTR::PDU::ASPA;

use warnings;
use strict;

use JSON::XS qw(encode_json decode_json);

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Utils qw(inet_pton
                               inet_ntop
                               dprint
                               recv_all);

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
    # Once servers all support 11, which requires that the AFI flags
    # be set, this can be restored.  (stayrtr sets this value to 0.)
    # if (not $args{'afi_flags'}) {
    #    die "Expected AFI flags";
    # }

    my $self = {
        version       => $args{'version'},
        flags         => $args{'flags'},
        customer_asn  => $args{'customer_asn'},
        provider_asns => $args{'provider_asns'},
        afi_flags     => $args{'afi_flags'},
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

    return pack("CCnNCCnNN$pc",
                $self->version(),
                $self->type(),
                0,
                16 + (4 * $pc),
                $self->flags(),
                # Always IPv4 and IPv6.
                3,
                $pc,
                $self->customer_asn(),
                @{$self->provider_asns()});
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    my $buf = recv_all($socket, 8);
    my ($flags, $afi_flags, $provider_count, $customer_asn) =
	unpack("CCnN", $buf);
    $buf = recv_all($socket, $provider_count * 4);
    my @provider_asns = unpack("N$provider_count", $buf);

    return
        APNIC::RPKI::RTR::PDU::ASPA->new(
            version       => $version,
            flags         => $flags,
            afi_flags     => $afi_flags,
            customer_asn  => $customer_asn,
            provider_asns => \@provider_asns,
        );
}

sub serialise_json
{
    my ($self) = @_;

    return encode_json({%{$self}, type => $self->type()});
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
                and ($self->afi_flags() == $other->afi_flags())
                and ($self->flags() == $other->flags()));
}

sub supported_in_version
{
    my ($self, $version) = @_;

    return ($version == 2);
}

1;
