package APNIC::RPKI::RTR::PDU::ResetQuery;

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
        version => $args{'version'},
    };
    bless $self, $class;
    return $self;
}

sub type
{
    return PDU_RESET_QUERY();
}

sub type_str
{
    return 'Reset Query';
}

sub version
{
    my ($self) = @_;

    return $self->{'version'};
}

sub serialise_binary
{
    my ($self) = @_;

    return pack("CCnN",
                $self->version(),
                $self->type(),
                get_zero(16),
                8);
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    if ($length != 8) {
        die "Expected length of 8 for Reset Query PDU, ".
            "but got '$length'.";
    }

    return
        APNIC::RPKI::RTR::PDU::ResetQuery->new(
            version => $version,
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
    return 0;
}

sub equals
{
    my ($self, $other) = @_;

    return (($self->type() == $other->type())
                and ($self->version() == $other->version()));
}

sub supported_in_version
{
    my ($self, $version) = @_;

    return (($version >= 0) and ($version <= 2));
}

1;
