package APNIC::RPKI::RTR::Session;

use warnings;
use strict;

use Math::BigInt;

my $MAX_SERIAL_NUMBER = Math::BigInt->new(1)->blsft(32)->bsub(1);

sub new
{
    my $class = shift;
    my %args = @_;

    my $session_id = $args{'session_id'};
    if (not $session_id) {
        die "No session ID provided.";
    }
    if ($session_id !~ /^\d+$/) {
        die "Session ID must be a number.";
    }
    if (not ($session_id > 0 and $session_id <= 65535)) {
        die "Session ID must be 16-bit unsigned integer.";
    }

    my $serial_number = $args{'serial_number'};
    if (not $serial_number) {
        die "No serial number provided.";
    }
    if ($serial_number !~ /^\d+$/) {
        die "Serial number must be a number.";
    }
    my $bi_serial_number =
        Math::BigInt->new($serial_number);
    if ($bi_serial_number->bgt($MAX_SERIAL_NUMBER)) {
        die "Serial number must be unsigned 32-bit integer.";
    }

    my $self = {
        session_id    => $session_id,
        serial_number => $serial_number,
        vrps          => {},
        rks           => {}
    };
    bless $self, $class;

    return $self;
}

1;
