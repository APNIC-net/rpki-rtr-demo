package APNIC::RPKI::RTR::PDU::RouterKey;

use warnings;
use strict;

use JSON::XS qw(encode_json decode_json);

use APNIC::RPKI::RTR::Utils qw(dprint
                               recv_all);

use base qw(APNIC::RPKI::RTR::PDU);

sub new
{
    my $class = shift;
    my %args = @_;

    my $self = {
        version       => $args{'version'},
        flags         => $args{'flags'},
        ski           => $args{'ski'},
        asn           => $args{'asn'},
        spki          => $args{'spki'},
    };
    bless $self, $class;
    return $self;
}

sub type
{
    return 9;
}

sub type_str
{
    return 'Router Key';
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

sub ski
{
    my ($self) = @_;

    return $self->{'ski'};
}

sub asn
{
    my ($self) = @_;

    return $self->{'asn'};
}

sub spki
{
    my ($self) = @_;

    return $self->{'spki'};
}

sub serialise_binary
{
    my ($self) = @_;

    my $ski_bi = Math::BigInt->new($self->ski());
    my $mask = Math::BigInt->new(1)->blsft(32)->bsub(1);
    my $ski1 = $ski_bi->copy()->brsft(128)->band($mask);
    my $ski2 = $ski_bi->copy()->brsft(96)->band($mask);
    my $ski3 = $ski_bi->copy()->brsft(64)->band($mask);
    my $ski4 = $ski_bi->copy()->brsft(32)->band($mask);
    my $ski5 = $ski_bi->copy()->band($mask);

    my $spki_len = length($self->spki());

    return pack("CCCCNNNNNNNa$spki_len",
                $self->version(),
                $self->type(),
                $self->flags(),
                0,
                32 + $spki_len,
                $ski1,
                $ski2,
                $ski3,
                $ski4,
                $ski5,
                $self->asn(),
                $self->spki());
}

sub deserialise_binary
{
    my ($class, $version, $session_id, $length, $socket) = @_;

    my $buf = recv_all($socket, ($length - 8));
    my $spki_len = $length - 32;

    my ($ski1, $ski2, $ski3, $ski4, $ski5, $asn, $spki) =
	unpack("NNNNNNa$spki_len", $buf);

    my $bi1 = Math::BigInt->new($ski1)->blsft(128);
    my $bi2 = Math::BigInt->new($ski2)->blsft(96);
    my $bi3 = Math::BigInt->new($ski3)->blsft(64);
    my $bi4 = Math::BigInt->new($ski4)->blsft(32);
    my $bi5 = Math::BigInt->new($ski5);
    my $ski_bi =
	Math::BigInt->new($bi1)->badd($bi2)->badd($bi3)->badd($bi4)->badd($bi5);

    my $flags = ($session_id >> 8) & 0xFF;

    return
        APNIC::RPKI::RTR::PDU::RouterKey->new(
            version => $version,
            flags   => $flags,
            asn     => $asn,
            ski     => $ski_bi->bstr(),
            spki    => $spki
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

    return ($other->type() == $self->type()
            and ($self->version() eq $other->version())
            and ($self->asn() == $other->asn())
            and ($self->ski() eq $other->ski())
            and ($self->spki() eq $other->spki())
            and ($self->flags() xor $other->flags()));
}

sub equals
{
    my ($self, $other) = @_;

    return ($other->type() == $self->type()
            and ($self->version() eq $other->version())
            and ($self->asn() == $other->asn())
            and ($self->ski() eq $other->ski())
            and ($self->spki() eq $other->spki())
            and ($self->flags() == $other->flags()));
}

sub supported_in_version
{
    my ($self, $version) = @_;

    return (($version == 1) or ($version == 2));
}

1;
