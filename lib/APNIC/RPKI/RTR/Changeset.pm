package APNIC::RPKI::RTR::Changeset;

use warnings;
use strict;

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::PDU::Utils qw(order_pdus
                                    is_data_pdu_type);

use JSON::XS qw(decode_json encode_json);

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
    return is_data_pdu_type($type);
}

sub add_pdu
{
    my ($self, $pdu) = @_;

    push @{$self->{'pdus'}}, $pdu; 

    return 1;
}

sub rationalise
{
    my ($self) = @_;

    my @final_pdus;
    PDU: for my $pdu ($self->pdus()) {
        for (my $i = 0; $i < @final_pdus; $i++) {
            my $fp = $final_pdus[$i];
            if ($pdu->is_reversal_of($fp)) {
                splice(@final_pdus, $i, 1);
                next PDU;
            } elsif (($pdu->type() == PDU_ASPA())
                        and ($fp->type() == PDU_ASPA())
                        and ($pdu->flags() == 1)
                        and ($fp->flags() == 1)
                        and ($pdu->customer_asn() == $fp->customer_asn())) {
                my %provider_asns =
                    map { $_ => 1 }
                        (@{$fp->provider_asns()},
                         @{$pdu->provider_asns()});
                my @final_provider_asns =
                    sort keys %provider_asns;
                $pdu->{'provider_asns'} =
                    \@final_provider_asns;
                splice(@final_pdus, $i, 1);
            }
        }
        push @final_pdus, $pdu;
    }
            
    $self->{'pdus'} = \@final_pdus;

    return 1;
}

sub apply_changeset
{
    my ($self, $changeset) = @_;

    push @{$self->{'pdus'}},
         @{$changeset->{'pdus'}};
    $self->rationalise();
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

    return order_pdus($self->_pdus());
}

sub _pdus
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
