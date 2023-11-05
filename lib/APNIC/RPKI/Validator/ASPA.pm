package APNIC::RPKI::Validator::ASPA;

use warnings;
use strict;

use APNIC::RPKI::RTR::Utils qw(dprint);

sub aspa_hop_check
{
    my ($aspas, $f, $s) = @_;

    if (not defined $f) {
        die "no first ASN passed to aspa_hop_check";
    }
    if (not defined $s) {
        die "no second ASN passed to aspa_hop_check";
    }

    if (not $aspas->{$f}) {
        return "no-attestation";
    }

    my %spas = map { $_ => 1 } @{$aspas->{$f} || []};
    if ($spas{$s}) {
        return "provider";
    }

    return "not-provider";
}

sub upstream
{
    my ($state, $prefix, $as_path_pre) = @_;

    dprint("validation-aspa: begin validation");

    my $aspas = $state->{'aspas'};
    my $str = "$prefix (upstream): {".(join ', ', @{$as_path_pre})."}";

    # 2.  Collapse prepends in the AS_SEQUENCE(s) in the AS_PATH (i.e.,
    #     keep only the unique AS numbers).  Let the resulting ordered
    #     sequence be represented by {AS(N), AS(N-1), ..., AS(2), AS(1)},
    #     where AS(1) is the first-added (i.e., origin) AS and AS(N) is the
    #     last-added AS and neighbor to the receiving/validating AS.

    my @as_path;
    for my $asn (reverse @{$as_path_pre}) {
        if (@as_path and $as_path[$#as_path] == $asn) {
            next;
        } else {
            push @as_path, $asn;
        }
    }
    my $n = scalar @as_path;

    # 3.  If N = 1, then the procedure halts with the outcome "Valid".
    #     Else, continue.

    if ($n == 1) {
        dprint("validation-aspa: completed: $str: valid");
        return 2;
    }

    # 4.  At this step, N >= 2.  If there is an i such that 2 <= i <= N and
    #     hop(AS(i-1), AS(i)) = "Not Provider+", then the procedure halts
    #     with the outcome "Invalid".  Else, continue.

    dprint("validation-aspa: debug: $str: begin NP+ check");
    for (my $i = 1; $i < $n; $i++) {
        my $index = $i + 1;
        my $f = $as_path[$i - 1];
        my $s = $as_path[$i];
        my $ahc = aspa_hop_check($aspas, $f, $s);
        dprint("validation-aspa: debug: $str: NP+ check at $index: AS$f, AS$s -> $ahc");
        if ($ahc eq "not-provider") {
            dprint("validation-aspa: completed: $str: invalid (found non-provider hop)");
            return 0;
        }
    }
    dprint("validation-aspa: debug: $str: past NP+ check (none found)");

    # 5.  If there is an i such that 2 <= i <= N and hop(AS(i-1), AS(i)) =
    #     "No Attestation", then the procedure halts with the outcome
    #     "Unknown".  Else, the procedure halts with the outcome "Valid".

    dprint("validation-aspa: debug: $str: begin NA check");
    for (my $i = 1; $i < $n; $i++) {
        my $index = $i + 1;
        my $f = $as_path[$i - 1];
        my $s = $as_path[$i];
        my $ahc = aspa_hop_check($aspas, $f, $s);
        dprint("validation-aspa: debug: $str: NA check at $index: AS$f, AS$s -> $ahc");
        if ($ahc eq "no-attestation") {
            dprint("validation-aspa: completed: $str: unknown (found no-attestation hop)");
            return 1;
        }
    }

    dprint("validation-aspa: debug: $str: past NA check (none found)");
    dprint("validation-aspa: completed: $str: valid (each hop is customer to provider)");

    return 2;
}

sub downstream
{
    my ($state, $prefix, $as_path_pre) = @_;

    my $aspas = $state->{'aspas'};
    my $str = "$prefix (downstream): {".(join ', ', @{$as_path_pre})."}";

    # 2.  Collapse prepends in the AS_SEQUENCE(s) in the AS_PATH (i.e.,
    #     keep only the unique AS numbers).  Let the resulting ordered
    #     sequence be represented by {AS(N), AS(N-1), ..., AS(2), AS(1)},
    #     where AS(1) is the first-added (i.e., origin) AS and AS(N) is the
    #     last-added AS and neighbor to the receiving/validating AS.
 
    my @as_path;
    for my $asn (reverse @{$as_path_pre}) {
        if (@as_path and $as_path[$#as_path] == $asn) {
            next;
        } else {
            push @as_path, $asn;
        }
    }
    my $n = scalar @as_path;

    # 3.  If 1 <= N <= 2, then the procedure halts with the outcome
    #     "Valid".  Else, continue.
        
    if (@as_path >= 1 and @as_path <= 2) {
        dprint("validation-aspa: completed: $str: valid");
        return 2;
    }

    # 4.  At this step, N >= 3.  Given the above-mentioned ordered
    #     sequence, find the lowest value of u (2 <= u <= N) for which
    #     hop(AS(u-1), AS(u)) = "Not Provider+".  Call it u_min.  If no
    #     such u_min exists, set u_min = N+1.    

    dprint("validation-aspa: debug: $str: begin u_min checks");
    my $u_min;
    for (my $i = 1; $i < $n; $i++) {
        my $new_u_min = $i + 1;
        my $f = $as_path[$i - 1];
        my $s = $as_path[$i];
        my $ahc = aspa_hop_check($aspas, $f, $s);
        dprint("validation-aspa: debug: $str u_min check at $new_u_min: AS$f, AS$s -> $ahc");
        if ($ahc eq "not-provider") {
            $u_min = $new_u_min;
            dprint("validation-aspa: debug: $str: found non-provider hop (start of first down-ramp): u_min is $u_min");
            last;
        }
    }
    if (not defined $u_min) {
        $u_min = $n + 1;
        dprint("validation-aspa: debug: $str: did not find non-provider hop (start of first down-ramp): u_min is $u_min");
    }

    #     Find the highest value of v (N-1 >= v >= 1) for which
    #     hop(AS(v+1), AS(v)) = "Not Provider+".  Call it v_max.  If
    #     no such v_max exists, then set v_max = 0.

    dprint("validation-aspa: debug: $str: begin v_max checks");
    my $v_max;
    for (my $i = ($n - 2); $i >= 0; $i--) {
        my $new_v_max = $i + 1;
        my $f = $as_path[$i];
        my $s = $as_path[$i + 1];
        my $ahc = aspa_hop_check($aspas, $s, $f);
        dprint("validation-aspa: debug: $str: v_max check at $new_v_max: AS$s, AS$f -> $ahc");
        if ($ahc eq "not-provider") {
            $v_max = $new_v_max;
            dprint("validation-aspa: debug: $str: found non-provider hop (start of last up-ramp): v_max is now $v_max");
            last;
        }
    }
    if (not defined $v_max) {
        $v_max = 0;
        dprint("validation-aspa: debug: $str: did not find non-provider hop (start of last up-ramp): v_max is $v_max");
    }

    dprint("validation-aspa: debug: $str: u_min: $u_min, v_max: $v_max");

    #     If u_min <= v_max, then the procedure halts with the outcome
    #     "Invalid".  Else, continue.

    if ($u_min <= $v_max) {
        dprint("validation-aspa: completed: $str: invalid (u_min is less than or equal to v_max, i.e. first down-ramp is before or at last up-ramp)");
        return 0;
    } else {
        dprint("validation-aspa: debug: $str: proceed: u_min is greater than v_max, i.e. first down-ramp is after last up-ramp");
    }

    # 5.  Up-ramp: For 2 <= i <= N, determine the largest K such that
    #     hop(AS(i-1), AS(i)) = "Provider+" for each i in the range 2 <= i
    #     <= K.  If such a largest K does not exist, then set K = 1.

    dprint("validation-aspa: debug: $str: begin up-ramp checks");
    my $k;
    for (my $i = 1; $i < $n; $i++) {
        my $new_k = $i + 1;
        my $f = $as_path[$i - 1] ;
        my $s = $as_path[$i];
        my $ahc = aspa_hop_check($aspas, $f, $s);
        dprint("validation-aspa: debug: $str: up-ramp check at $new_k: AS$f, AS$s -> $ahc");
        if ($ahc ne "provider") {
            last;
        } else {
            $k = $new_k;
        }
    }
    if (not defined $k) {
        $k = 1;
    }
    dprint("validation-aspa: debug: $str: K is $k");

    # 6.  Down-ramp: For N-1 >= j >= 1, determine the smallest L such that
    #     hop(AS(j+1), AS(j)) = "Provider+" for each j in the range N-1 >=
    #     j >= L.  If such smallest L does not exist, then set L = N.

    dprint("validation-aspa: debug: $str: begin down-ramp checks");
    my $l;
    for (my $j = $n - 2; $j >= 0; $j--) {
        my $new_l = $j + 1;
        my $f = $as_path[$j + 1];
        my $s = $as_path[$j];
        my $ahc = aspa_hop_check($aspas, $f, $s);
        dprint("validation-aspa: debug: $str: down-ramp check at $new_l: AS$f, AS$s -> $ahc");
        if ($ahc ne "provider") {
            last;
        } else {
            $l = $new_l;
        }
    }
    if (not defined $l) {
        $l = $n;
    }
    dprint("validation-aspa: debug: $str: L is $l");

    # 7.  If L-K <= 1, then the procedure halts with the outcome "Valid".
    #     Else, the procedure halts with the outcome "Unknown".

    if ($l - $k <= 1) {
        dprint("validation-aspa: completed: $str: valid (L - K <= 1)");
        return 2;
    } else {
        dprint("validation-aspa: completed: $str: unknown (L - K > 1)");
        return 1;
    }
}

sub validate
{
    my ($state, $provider_asns, $announcement_str) = @_;

    my @elements = split /\|/, $announcement_str;
    my $prefix = $elements[5];
    my $source = $elements[4];
    my $path_str = $elements[6];
    my @path = split /\s+/, $path_str;

    if ($provider_asns->{$source}) {
        return downstream($state, $prefix, \@path);
    } else {
        return upstream($state, $prefix, \@path);
    }
}

1;
