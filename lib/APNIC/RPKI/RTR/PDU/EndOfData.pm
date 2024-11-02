package APNIC::RPKI::RTR::PDU::EndOfData;

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

    if (not defined $args{'serial_number'}) {
        die "No serial number provided";
    }

    my $self = {
        version          => $args{'version'},
        session_id       => $args{'session_id'},
        serial_number    => $args{'serial_number'},
        refresh_interval => $args{'refresh_interval'},
        retry_interval   => $args{'retry_interval'},
        expire_interval  => $args{'expire_interval'},
    };
    bless $self, $class;
    return $self;
}

sub type
{
    return PDU_END_OF_DATA();
}

sub type_str
{
    return 'End of Data';
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

sub refresh_interval
{
    my ($self) = @_;
    
    return $self->{'refresh_interval'};
}

sub retry_interval
{
    my ($self) = @_;
    
    return $self->{'retry_interval'};
}

sub expire_interval
{
    my ($self) = @_;
    
    return $self->{'expire_interval'};
}

sub serialise_binary
{
    my ($self) = @_;

    if ($self->version() == 0) {
        return pack("CCnNN",
                    $self->version(),
                    $self->type(),
                    $self->session_id(),
                    12,
                    $self->serial_number())
    } else {
        return pack("CCnNNNNN",
                    $self->version(),
                    $self->type(),
                    $self->session_id(),
                    24,
                    $self->serial_number(),
                    $self->refresh_interval(),
                    $self->retry_interval(),
                    $self->expire_interval());
    }
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    if ($version == 0) {
        if ($length != 12) {
            die "Expected length of 24 for End of Data PDU, ".
                "but got '$length'.";
        }

        my $buf = recv_all($socket, 4);
        my ($serial_number) = unpack("N", $buf);

        return
            APNIC::RPKI::RTR::PDU::EndOfData->new(
                version          => $version,
                session_id       => $session_id,
                serial_number    => $serial_number,
            );
    } else {
        if ($length != 24) {
            die "Expected length of 24 for End of Data PDU, ".
                "but got '$length'.";
        }

        my $buf = recv_all($socket, 16);
        my ($serial_number, $refresh_interval,
            $retry_interval, $expire_interval) =
            unpack("NNNN", $buf);

        return
            APNIC::RPKI::RTR::PDU::EndOfData->new(
                version          => $version,
                session_id       => $session_id,
                serial_number    => $serial_number,
                refresh_interval => $refresh_interval,
                retry_interval   => $retry_interval,
                expire_interval  => $expire_interval,
            );
    }
}

sub serialise_json
{
    my ($self) = @_;

    if ($self->version() == 0) {
        my %data = %{$self};
        delete $data{qw(refresh_interval
                        retry_interval
                        expire_interval)};
        return encode_json({%data, type => $self->type()});
    } else {
        return encode_json({%{$self}, type => $self->type()});
    }
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
                and ($self->version() == $other->version())
                and ($self->session_id() == $other->session_id())
                and ($self->serial_number() == $other->serial_number())
                and (($self->refresh_interval() || 0) == ($other->refresh_interval() || 0))
                and (($self->retry_interval() || 0) == ($other->retry_interval() || 0))
                and (($self->expire_interval() || 0) == ($other->expire_interval() || 0)));
}

sub supported_in_version
{
    my ($self, $version) = @_;

    return (($version >= 0) and ($version <= 2));
}

1;
