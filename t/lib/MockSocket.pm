package MockSocket;

use warnings;
use strict;

use List::Util qw(min);

use APNIC::RPKI::RTR::Utils qw(dprint);

sub new
{
    my $class = shift;
    my $buf = shift;

    my $self = { buf    => $buf,
                 len    => length($buf),
                 offset => 0 };
    bless $self, $class;

    return $self;
}

sub recv
{
    my $self = $_[0];
    my $len  = $_[2];

    dprint("mock socket: requesting '$len' bytes");

    my $buflen = $self->{'len'};
    my $offset = $self->{'offset'};
    my $uselen = min($buflen - $offset, $len);
    dprint("mock socket: returning '$uselen' bytes");
    $_[1] .= substr($self->{'buf'}, $self->{'offset'}, $uselen);
    my $rbuflen = length($_[1]);
    dprint("mock socket: rbuf now contains '$rbuflen' bytes");
    $self->{'offset'} += $uselen;
    dprint("mock socket: offset is now '".$self->{'offset'}."'");
    return 1;
}

sub exhausted
{
    my ($self) = @_;

    return ($self->{'len'} == $self->{'offset'});
}

1;
