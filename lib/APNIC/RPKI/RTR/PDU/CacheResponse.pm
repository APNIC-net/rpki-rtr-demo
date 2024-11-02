package APNIC::RPKI::RTR::PDU::CacheResponse;

use warnings;
use strict;

use JSON::XS qw(encode_json decode_json);

use APNIC::RPKI::RTR::Constants;

use base qw(APNIC::RPKI::RTR::PDU);

sub new
{
    my $class = shift;
    my %args = @_;

    my $self = {
        version    => $args{'version'},
        session_id => $args{'session_id'},
    };
    bless $self, $class;
    return $self;
}

sub type
{
    return PDU_CACHE_RESPONSE();
}

sub type_str
{
    return 'Cache Response';
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

sub serialise_binary
{
    my ($self) = @_;

    return pack("CCnN",
                $self->version(),
                $self->type(),
                $self->session_id(),
                8);
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    if ($length != 8) {
        die "Expected length of 8 for Cache Response PDU, ".
            "but got '$length'.";
    }

    return
        APNIC::RPKI::RTR::PDU::CacheResponse->new(
            version    => $version,
            session_id => $session_id,
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

    return (($self->version() == $other->version())
                and ($self->session_id() == $other->session_id()));
}

sub supported_in_version
{
    my ($self, $version) = @_;

    return (($version >= 0) and ($version <= 2));
}

1;
