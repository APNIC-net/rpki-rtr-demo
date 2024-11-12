package APNIC::RPKI::RTR::Socket::SSH;

use warnings;
use strict;

use IPC::Open2 qw(open2);

sub new
{
    my $class = shift;
    my %args = @_;

    my $server = $args{'server'};
    my $port = $args{'port'} || 22;
    my @options = (
        "-p $port"
    );
    if (my $kh = $args{'known_hosts'}) {
        push @options, "-o UserKnownHostsFile=$kh";
    }
    if (my $id = $args{'ssh_key'}) {
        push @options, "-i $id";
    }
    my $cmd = "ssh ".(join ' ', @options)." $server -s rpki-rtr";
    my $pid = open2(my $out, my $in, $cmd);

    my $self = {
        in   => $in,
        out  => $out,
        pid  => $pid,
        args => \%args
    };
    bless $self, $class;
    return $self;
}

sub send
{
    my ($self, $data) = @_;

    my $in = $self->{'in'};
    print $in $data;

    return length($data);
}

sub recv
{
    my $res = sysread($_[0]->{'out'}, $_[1], $_[2]);

    return $res;
}

sub setsockopt
{
    return 1;
}

sub peerport
{
    return 65535;
}

sub shutdown
{
    my ($self) = @_;

    kill('TERM', $self->{'pid'});
}

sub close
{
    return 1;
}

1;
