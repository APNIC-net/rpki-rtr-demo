#!/usr/bin/perl

use warnings;
use strict;

use List::MoreUtils qw(uniq);

sub get_data
{
    my ($name) = @_;

    my @lines = `perl -Mblib interop/servers/$name.pl`;
    chomp for @lines;
    @lines = grep { /^$name,/ } @lines;
    @lines = map { my @els = split /,/, $_; \@els } @lines;
    return @lines;
}

my @openrtrd = get_data("openrtrd");
my $openrtrd_version = $openrtrd[0]->[1];

my @rtrtr = get_data("rtrtr");
my $rtrtr_version = $rtrtr[0]->[1];

my @rpki_rtr_demo = get_data("rpki-rtr-demo");
my $rpki_rtr_demo_version = $rpki_rtr_demo[0]->[1];

my @table;
push @table, ["", "openrtrd ($openrtrd_version)",
              "rtrtr ($rtrtr_version)",
              "rpki-rtr-demo ($rpki_rtr_demo_version)"];

my @table_lengths =
    ((scalar @openrtrd),
     (scalar @rtrtr),
     (scalar @rpki_rtr_demo));
my @utls = uniq @table_lengths;
if (@utls != 1) {
    use Data::Dumper;
    warn Dumper(\@openrtrd, \@rtrtr, \@rpki_rtr_demo);
    die "tests should produce same table lengths";
}

for (my $i = 0; $i < @openrtrd; $i++) {
    my $line1   = $openrtrd[$i];
    my $name1   = $line1->[2];
    my $result1 = $line1->[3];

    my $line2   = $rtrtr[$i];
    my $name2   = $line2->[2];
    my $result2 = $line2->[3];

    my $line3   = $rpki_rtr_demo[$i];
    my $name3   = $line3->[2];
    my $result3 = $line3->[3];

    my @names = uniq($name1, $name2, $name3);
    if (@names != 1) {
        use Data::Dumper;
        warn Dumper(\@openrtrd, \@rtrtr, \@rpki_rtr_demo);
        die "names at index $i are not the same";
    }

    push @table, [$name1, $result1, $result2, $result3];
}

my @lines;
for my $entry (@table) {
    my $values = join " | ", @{$entry};
    $values = "| $values |";
    push @lines, $values;
}
splice @lines, 1, 0, ("| - | - | - | - |");
for my $line (@lines) {
    print "$line\n";
}

1;
