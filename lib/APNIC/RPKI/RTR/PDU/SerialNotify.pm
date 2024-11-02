package APNIC::RPKI::RTR::PDU::SerialNotify;

use warnings;
use strict;

use JSON::XS qw(encode_json decode_json);

use APNIC::RPKI::RTR::Constants;
use APNIC::RPKI::RTR::Utils qw(recv_all);

use base qw(APNIC::RPKI::RTR::PDU);

sub new
{
    my $class = shift;
    my %args = @_;

    my $self = {
        version       => $args{'version'},
        session_id    => $args{'session_id'},
        serial_number => $args{'serial_number'},
    };
    bless $self, $class;
    return $self;
}

sub type
{
    return PDU_SERIAL_NOTIFY();
}

sub type_str
{
    return 'Serial Notify';
}

sub version
{
    my ($self) = @_;

    return $self->{'version'};
}

sub session_id
{
    my ($self) = @_;
    
    return $self->{'session_id'};
}

sub serial_number
{
    my ($self) = @_;
    
    return $self->{'serial_number'};
}

sub serialise_binary
{
    my ($self) = @_;

    return pack("CCnNN",
                $self->version(),
                $self->type(),
                $self->session_id(),
                12,
                $self->serial_number());
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    if ($length != 12) {
        die "Expected length of 12 for Serial Notify PDU, ".
            "but got '$length'.";
    }

    my $buf = recv_all($socket, 4);
    my $serial_number = unpack("N", $buf);

    return
        APNIC::RPKI::RTR::PDU::SerialNotify->new(
            version       => $version,
            session_id    => $session_id,
            serial_number => $serial_number,
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
                and ($self->serial_number() == $other->serial_number())
                and ($self->version() == $other->version())
                and ($self->session_id() == $other->session_id()));
}

sub supported_in_version
{
    my ($self, $version) = @_;

    return (($version >= 0) and ($version <= 2));
}

1;
