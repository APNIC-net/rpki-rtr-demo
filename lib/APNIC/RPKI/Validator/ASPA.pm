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
    my ($state, $prefix, $as_path,
        $max_up_ramp, $min_up_ramp, $max_down_ramp, $min_down_ramp) = @_;

    dprint("validation-aspa: upstream");
    dprint("validation-aspa: max_up_ramp: $max_up_ramp");
    dprint("validation-aspa: min_up_ramp: $min_up_ramp");
    dprint("validation-aspa: max_down_ramp: $max_down_ramp");
    dprint("validation-aspa: min_down_ramp: $min_down_ramp");

    # 1.  If the AS_PATH is empty, then the procedure halts with the
    #     outcome "Invalid".

    if (@{$as_path} == 0) {
        dprint("validation-aspa: empty AS path: invalid");
        return 0;
    }

    # 2.  If the receiving AS is not an RS-client and the most recently
    #     added AS in the AS_PATH does not match the neighbor AS, then the
    #     procedure halts with the outcome "Invalid".

    # 2 is not relevant to this validation function.

    # 3.  If the AS_PATH has an AS_SET, then the procedure halts with the
    #     outcome "Invalid".

    # 3 is not relevant to this validation function.

    # 4.  If max_up_ramp < N, the procedure halts with the outcome
    #     "Invalid".

    if ($max_up_ramp < @{$as_path}) {
        dprint("validation-aspa: max_up_ramp < N: invalid");
        return 0;
    }

    # 5.  If min_up_ramp < N, the procedure halts with the outcome
    #     "Unknown".

    if ($min_up_ramp < @{$as_path}) {
        dprint("validation-aspa: min_up_ramp < N: unknown");
        return 1;
    }

    # 6.  Else, the procedure halts with the outcome "Valid". 

    dprint("validation-aspa: valid");
    return 2;
}

sub downstream
{
    my ($state, $prefix, $as_path,
        $max_up_ramp, $min_up_ramp, $max_down_ramp, $min_down_ramp) = @_;

    dprint("validation-aspa: downstream");
    dprint("validation-aspa: max_up_ramp: $max_up_ramp");
    dprint("validation-aspa: min_up_ramp: $min_up_ramp");
    dprint("validation-aspa: max_down_ramp: $max_down_ramp");
    dprint("validation-aspa: min_down_ramp: $min_down_ramp");

    # 1.  If the AS_PATH is empty, then the procedure halts with the
    #     outcome "Invalid".

    if (@{$as_path} == 0) {
        dprint("validation-aspa: empty AS path: invalid");
        return 0;
    }

    # 2.  If the most recently added AS in the AS_PATH does not match the
    #     neighbor AS, then the procedure halts with the outcome "Invalid".

    # 2 is not relevant to this validation function.

    # 3.  If the AS_PATH has an AS_SET, then the procedure halts with the
    #     outcome "Invalid".

    # 3 is not relevant to this validation function.

    # 4.  If max_up_ramp + max_down_ramp < N, the procedure halts with the
    #     outcome "Invalid".

    if (($max_up_ramp + $max_down_ramp) < @{$as_path}) {
        dprint("validation-aspa: max_up_ramp + max_down_ramp < N: invalid");
        return 0;
    }

    # 5.  If min_up_ramp + min_down_ramp < N, the procedure halts with the
    #     outcome "Unknown".

    if (($min_up_ramp + $min_down_ramp) < @{$as_path}) {
        dprint("validation-aspa: min_up_ramp + min_down_ramp < N: unknown");
        return 1;
    }

    # 6.  Else, the procedure halts with the outcome "Valid".

    dprint("validation-aspa: valid");
    return 2;
}

sub validate
{
    my ($state, $provider_asns, $announcement_str) = @_;

    my @elements = split /\|/, $announcement_str;
    my $prefix = $elements[5];
    my $source = $elements[4];
    my $path_str = $elements[6];
    my @path = split /\s+/, $path_str;

    # Calculate the inputs to the upstream/downstream functions.

    # Let the sequence {AS(N), AS(N-1),..., AS(2), AS(1)} represent
    # the AS_PATH in terms of unique ASNs, where AS(1) is the origin
    # AS and AS(N) is the most recently added AS and neighbor of the
    # receiving/ verifying AS.

    my @as_path;
    for my $asn (reverse @path) {
        if (@as_path and $as_path[$#as_path] == $asn) {
            next;
        } else {
            push @as_path, $asn;
        }
    }
    my $n = scalar @as_path;

    my $path_str_real = join " ", (reverse @as_path);
    dprint("validation-aspa: unique path: $path_str_real");

    my $aspas = $state->{'aspas'};

    # Determine the maximum up-ramp length as I, where I is the
    # minimum index for which authorized(A(I), A(I+1)) returns "Not
    # Provider+".  If there is no such I, the maximum up-ramp length
    # is set equal to the AS_PATH length N.  This parameter is
    # abbreviated as max_up_ramp.

    my $max_up_ramp;
    for (my $i = 0; $i < ($n - 1); $i++) {
        my $first = $as_path[$i];
        my $second = $as_path[$i + 1];
        my $hc = aspa_hop_check($aspas, $first, $second);
        dprint("validation-aspa: max_up_ramp check for ".
               "$first -> $second results in $hc");
        if ($hc eq "not-provider") {
            $max_up_ramp = $i + 1;
            dprint("validation-aspa: reached max_up_ramp ".
                   "($max_up_ramp) at $first -> $second ".
                   "($hc)");
            last;
        }
    }
    if (not defined $max_up_ramp) {
        dprint("validation-aspa: did not find not-provider hop ".
               "on up ramp, max_up_ramp defaults to $n");
        $max_up_ramp = $n;
    }

    # The minimum up-ramp length can be determined as I, where I is
    # the minimum index for which authorized(A(I), A(I+1)) returns "No
    # Attestation" or "Not Provider+".  If there is no such I, the
    # AS_PATH consists of only "Provider+" pairs; so the minimum
    # up-ramp length is set equal to the AS_PATH length N.  This
    # parameter is abbreviated as min_up_ramp.

    my $min_up_ramp;
    for (my $i = 0; $i < ($n - 1); $i++) {
        my $first = $as_path[$i];
        my $second = $as_path[$i + 1];
        my $hc = aspa_hop_check($aspas, $first, $second);
        dprint("validation-aspa: min_up_ramp check for ".
               "$first -> $second results in $hc");
        if ($hc eq "not-provider" or $hc eq "no-attestation") {
            $min_up_ramp = $i + 1;
            dprint("validation-aspa: reached min_up_ramp ".
                   "($min_up_ramp) at $first -> $second ".
                   "($hc)");
            last;
        }
    }
    if (not defined $min_up_ramp) {
        dprint("validation-aspa: did not find not-provider/".
               "no-attestation hop on up ramp, min_up_ramp ".
               "defaults to $n");
        $min_up_ramp = $n;
    }

    # Similarly, the maximum down-ramp length can be determined as N -
    # J + 1 where J is the maximum index for which authorized(A(J),
    # A(J-1)) returns "Not Provider+".  If there is no such J, the
    # maximum down- ramp length is set equal to the AS_PATH length N.
    # This parameter is abbreviated as max_down_ramp.

    my $max_down_ramp;
    for (my $i = ($n - 1); $i > 0; $i--) {
        my $first = $as_path[$i];
        my $second = $as_path[$i - 1];
        my $hc = aspa_hop_check($aspas, $first, $second);
        dprint("validation-aspa: max_down_ramp check for ".
               "$first -> $second results in $hc");
        if ($hc eq "not-provider") {
            my $j = $i + 1;
            $max_down_ramp = $n - $j + 1;
            dprint("validation-aspa: reached max_down_ramp ".
                   "($max_down_ramp) at $first -> $second ".
                   "($hc)");
            last;
        }
    }
    if (not defined $max_down_ramp) {
        dprint("validation-aspa: did not find not-provider hop ".
               "on down ramp, max_down_ramp defaults to $n");
        $max_down_ramp = $n;
    }

    # The minimum down-ramp length can be determined as N - J + 1
    # where J is the maximum index for which authorized(A(J), A(J-1))
    # returns "No Attestation" or "Not Provider+".  If there is no
    # such J, the minimum down-ramp length is set equal to the AS_PATH
    # length N.  This parameter is abbreviated as min_down_ramp.  

    my $min_down_ramp = $n;
    for (my $i = ($n - 1); $i > 0; $i--) {
        my $first = $as_path[$i];
        my $second = $as_path[$i - 1];
        my $hc = aspa_hop_check($aspas, $first, $second);
        dprint("validation-aspa: min_down_ramp check for ".
               "$first -> $second results in $hc");
        if ($hc eq "not-provider" or $hc eq "no-attestation") {
            my $j = $i + 1;
            $min_down_ramp = $n - $j + 1;
            dprint("validation-aspa: reached min_down_ramp ".
                   "($min_down_ramp) at $first -> $second ".
                   "($hc)");
            last;
        }
    }
    if (not defined $min_down_ramp) {
        dprint("validation-aspa: did not find not-provider/".
               "no-attestation hop on down ramp, min_down_ramp ".
               "defaults to $n");
        $min_down_ramp = $n;
    }

    if ($provider_asns->{$source}) {
        return downstream($state, $prefix, \@as_path,
                          $max_up_ramp, $min_up_ramp,
                          $max_down_ramp, $min_down_ramp);
    } else {
        return upstream($state, $prefix, \@as_path,
                        $max_up_ramp, $min_up_ramp,
                        $max_down_ramp, $min_down_ramp);
    }
}

1;
