package APNIC::RPKI::RTR::Utils;

use warnings;
use strict;

use Time::HiRes qw(sleep);

use Net::IP::XS qw(ip_bintoip
                   ip_inttobin
                   ip_iptobin
                   ip_bintoint
                   ip_expand_address
                   ip_compress_address);

use base qw(Exporter);

our @EXPORT_OK = qw(inet_ntop
                    inet_pton
                    dprint
                    recv_all);

sub inet_ntop
{
    my ($n, $version) = @_;

    my $bin = ip_inttobin($n, $version);
    if (not $bin) {
        die "Integer IP address '$n' is invalid ($version): ".
            $Net::IP::XS::ERROR;
    }

    my $ip = ip_bintoip($bin, $version);
    if ($version == 6) {
        $ip = ip_compress_address($ip, 6);
    }
    return $ip;
}

sub inet_pton
{
    my ($ip, $version) = @_;

    if ($version == 6) {
        $ip = ip_expand_address($ip, 6);
    }

    my $bin = ip_iptobin($ip, $version);
    if (not $bin) {
        die "IP address is invalid: '$ip' ($version): ".
            $Net::IP::XS::ERROR;
    }

    return ip_bintoint($bin, $version);
}

sub dprint
{
    my @msgs = @_;

    if ($ENV{'APNIC_DEBUG'}) {
        for my $msg (@msgs) {
            print STDERR "$$: $msg\n";
        }
    }
}

sub recv_all
{
    my ($socket, $length) = @_;

    my $limit = 30;
    my $buf = "";
    while ((length($buf) != $length) and ($limit > 0)) {
        my $tbuf = "";
        my $new_length = ($length - length($buf));
        dprint("recv_all: requesting '$new_length' bytes from socket");
        my $res = $socket->recv($tbuf, $new_length);
        if (not defined $res) {
            die "Unable to receive data from socket: $!";
        }
        $buf .= $tbuf;
        my $lb = length($buf);
        dprint("recv_all: buffer now contains '$lb' bytes");
        if (length($buf) != $length) {
            sleep(0.1);
        }
        $limit--;
    }
    if (length($buf) != $length) {
        die "Unable to receive data from socket (waited 3s)";
    }

    return $buf;
}

1;
