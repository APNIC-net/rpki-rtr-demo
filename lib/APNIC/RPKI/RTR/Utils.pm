package APNIC::RPKI::RTR::Utils;

use warnings;
use strict;

use Time::HiRes qw(sleep);

use IO::Socket qw(IPPROTO_TCP TCP_MD5SIG);
use IO::Socket::INET;
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
                    recv_all
                    get_zero
                    validate_intervals
                    socket_inet);

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

    my $limit = 10;
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
        if ($lb == 0) {
            # Socket is closed.
            return -1;
        }
        dprint("recv_all: buffer now contains '$lb' bytes");
        if (length($buf) != $length) {
            sleep(0.1);
        }
        $limit--;
    }
    if (length($buf) != $length) {
        die "Unable to receive data from socket (waited 1s)";
    }

    return $buf;
}

sub get_zero
{
    my ($bits) = @_;

    if (not $ENV{'APNIC_RANDOMISE_ZERO'}) {
        return 0;
    } else {
        dprint("randomising zero");
        my $num = int(rand(4294967295));
        my $mask = (1 << $bits) - 1;
        $num &= $mask;
        return $num;
    }
}

sub validate_intervals
{
    my ($refresh_interval, $retry_interval, $expire_interval) = @_;

    my $msg = "";
    if ($refresh_interval > 86400) {
        $msg = "refresh interval too large";
    } elsif ($retry_interval > 7200) {
        $msg = "retry interval too large";
    } elsif ($expire_interval < 600) {
        $msg = "expire interval too small";
    } elsif ($expire_interval > 172800) {
        $msg = "expire interval too large";
    } elsif ($expire_interval <= $refresh_interval) {
        $msg = "expire interval must be greater than ".
               "refresh interval";
    } elsif ($expire_interval <= $retry_interval) {
        $msg = "expire interval must be greater than ".
               "retry interval";
    }

    return $msg;
}

sub socket_inet
{
    my %args = @_;

    my $sock = IO::Socket->new();
    $sock->autoflush(1);
    ${*$sock}{'io_socket_timeout'} =
        delete $args{'Timeout'};
    bless $sock, 'IO::Socket::INET';

    my $arg = \%args;
    my ($rport, $raddr);

    if (exists $arg->{'LocalHost'}
            and not exists $arg->{'LocalAddr'}) {
        $arg->{'LocalAddr'} = $arg->{'LocalHost'};
    }

    my $laddr  = $arg->{'LocalAddr'};
    my $lport  = $arg->{'LocalPort'};
    my $listen = (exists $arg->{'Listen'} and $arg->{'Listen'});

    my $laddr_num;
    if (defined $laddr) {
        $laddr_num = inet_aton($laddr);
        if (not defined $laddr_num) {
            die "Bad hostname '$laddr'";
        }
    }

    if (exists $arg->{'PeerHost'}
            and not exists $arg->{'PeerAddr'}) {
        $arg->{'PeerAddr'} = $arg->{'PeerHost'};
    }

    if (not exists $arg->{'Listen'}) {
        $raddr = $arg->{'PeerAddr'};
        $rport = $arg->{'PeerPort'};
    }

    my $proto = IO::Socket::INET::_get_proto_number('tcp');
    my $type = $arg->{'Type'};

    my @raddr = ();
    if (defined $raddr) {
        @raddr = $sock->_get_addr($raddr, 0);
        if (not @raddr) {
            die "Bad hostname '$raddr'";
        }
    }

    for (;;) {
        my $res = $sock->socket(AF_INET, $type, $proto);
        if (not $res) {
            die "Unable to create socket: $!";
        }

        if (my $key = $arg->{'MD5Sig'}) {
            my $packed_sig =
                pack("SSA4x120x2Sx4",
                     AF_INET,
                     ($listen ? $lport     : $rport),
                     ($listen ? $laddr_num : inet_aton($raddr)),
                     length($key));
            $packed_sig .= $key;
            my $padding_count = 80 - length($key);
            my $padding = join '', map { chr(0) } (1..$padding_count);
            $packed_sig .= $padding;

            my $rc = $sock->setsockopt(IPPROTO_TCP, TCP_MD5SIG,
                                       $packed_sig);
            if (not $rc) {
                die "Failed to set MD5 signature option: $!";
            }
        }

        if ($arg->{'ReusePort'}) {
            my $res = $sock->sockopt(SO_REUSEPORT, 1);
            if (not $res) {
                die "Unable to set ReusePort: $!";
            }
        }

        if ($listen) {
            my $res = $sock->bind($lport || 0, $laddr_num);
            if (not $res) {
                die "Unable to bind socket: $!";
            }
            $res = $sock->listen($arg->{Listen} || 5);
            if (not $res) {
                die "Unable to listen for socket: $!";
            }
            last
        }

        $raddr = shift @raddr;

        if ($sock->connect(pack_sockaddr_in($rport, $raddr))) {
            return $sock;
        }

        if (not @raddr) {
            die "Timeout: $!, $@";
        }
    }

    $sock;
}

1;
