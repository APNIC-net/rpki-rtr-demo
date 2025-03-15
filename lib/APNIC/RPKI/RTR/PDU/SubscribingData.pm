package APNIC::RPKI::RTR::PDU::SubscribingData;

use warnings;
use strict;

use JSON::XS qw(encode_json decode_json);

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Utils qw(get_zero);

use base qw(APNIC::RPKI::RTR::PDU);

sub new
{
    my $class = shift;
    my %args = @_;

    my $self = {
        version    => $args{'version'},
        data_types => $args{'data_types'},
    };
    bless $self, $class;
    return $self;
}

sub type
{
    return PDU_SUBSCRIBING_DATA();
}

sub type_str
{
    return 'Subscribing Data';
}

sub version
{
    my ($self) = @_;

    return $self->{'version'};
}

sub data_types
{
    my ($self) = @_;

    return $self->{'data_types'};
}

sub serialise_binary
{
    my ($self) = @_;

    my @data_types = @{$self->data_types()};
    my $dc = scalar @data_types;

    return pack("CCnNC$dc",
                $self->version(),
                $self->type(),
                get_zero(16),
                8 + $dc);
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    my $dc = $length - 8;
    my $buf = recv_all($socket, $dc);
    my @data_types = unpack("C$dc", $buf);

    return
        APNIC::RPKI::RTR::PDU::SubscribingData->new(
            version    => $version,
            data_types => \@data_types
        );
}

sub serialise_json
{
    my ($self) = @_;

    return encode_json({%{$self}, type => $self->type(),
                        data_types => $self->data_types()});
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
    return 0;
}

sub equals
{
    my ($self, $other) = @_;

    if ($self->type() != $other->type()) {
        return;
    }

    my @self_data_types  = sort @{$self->data_types()};
    my @other_data_types = sort @{$other->data_types()};
    if (@self_data_types != @other_data_types) {
        return;
    }
    for (my $i = 0; $i < @self_data_types; $i++) {
        if ($self_data_types[$i] != $other_data_types[$i]) {
            return;
        }
    }

    return 1;
}

sub supported_in_version
{
    my ($self, $version) = @_;

    return (($version >= 0) and ($version <= 2));
}

1;
