package APNIC::RPKI::RTR::Changeset;

use warnings;
use strict;

use APNIC::RPKI::RTR::PDU::Utils;

use JSON::XS qw(decode_json encode_json);

my %ADDABLE_PDU_TYPES =
    map { $_ => 1 }
        qw(4 6 9 11);

sub new
{
    my $class = shift;
    my $self = {
        pdus                => [],
        first_serial_number => undef,
        last_serial_number  => undef,
    };
    bless $self, $class;
    return $self;
}

sub can_add_pdu
{
    my ($self, $pdu) = @_;

    my $type = $pdu->type();

    return $ADDABLE_PDU_TYPES{$type};
}

sub add_pdu
{
    my ($self, $pdu) = @_;

    push @{$self->{'pdus'}}, $pdu; 

    return 1;
}

sub apply_changeset
{
    my ($self, $changeset) = @_;

    my @final_pdus;
    PDU: for my $pdu (@{$changeset->{'pdus'}}) {
        for (my $i = 0; $i < @final_pdus; $i++) {
            my $fp = $final_pdus[$i];
            if ($pdu->is_reversal_of($fp)) {
                splice(@final_pdus, $i, 1);
                next PDU;
            }
        }
        push @final_pdus, $pdu;
    }
            
    $self->{'pdus'} = \@final_pdus;
    $self->{'last_serial_number'} =
        $changeset->{'last_serial_number'};

    return 1;
}

sub serialise_json
{
    my ($self) = @_;

    my @pdus =
        map { $_->serialise_json() }
            @{$self->{'pdus'}};

    my $data = encode_json({
        %{$self},
        pdus => \@pdus
    });
    return $data;
}

sub pdus
{
    my ($self) = @_;

    return @{$self->{'pdus'}};
}

sub deserialise_json
{
    my ($class, $ddata) = @_;

    my $data = decode_json($ddata);
    my @pdus =
        map { APNIC::RPKI::RTR::PDU::Utils::deserialise_json($_) }
            @{delete $data->{'pdus'}};
    my $self = {
        %{$data},
        pdus => \@pdus
    };
    bless $self, $class;
    return $self;
}

1;
