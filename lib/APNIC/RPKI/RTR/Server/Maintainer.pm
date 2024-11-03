package APNIC::RPKI::RTR::Server::Maintainer;

use warnings;
use strict;

use File::Slurp qw(read_file write_file);
use List::Util qw(max);

use APNIC::RPKI::RTR::Changeset;
use APNIC::RPKI::RTR::State;

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = {
        data_dir => $args{'data_dir'},
    };
    bless $self, $class;
    return $self;
}

sub apply_changeset
{
    my ($self, $changeset, $override_serial) = @_;

    $changeset->rationalise();

    my $data_dir = $self->{'data_dir'};
    my @contents = `ls $data_dir`;
    chomp for @contents;
    my @changeset_paths = grep { /changeset/ } @contents;
    my @serials;
    for my $changeset_path (@changeset_paths) {
        my ($serial) = ($changeset_path =~ /changeset_(\d+)\./);
        if ($serial) {
            push @serials, $serial;
        }
    }
    my $max_serial;
    if (@serials) {
        @serials = sort @serials;
        $max_serial = $serials[$#serials];
        # If both the top serial value and 1 are present as serials,
        # then remove everything from the top of the list working
        # backwards, for the purposes of figuring out the next serial.
        if (($max_serial == 4294967295)
                and ($serials[0] == 1)) {
            while ($serials[$#serials] == $max_serial) {
                pop @serials;
                $max_serial--;
            }
            $max_serial = $serials[$#serials];
        }
    } elsif ($override_serial) {
        $max_serial = $override_serial;
    } else {
        $max_serial = 0;
    }
    if (defined $override_serial
            and $max_serial != $override_serial) {
        die "Override serial not used";
    }

    my $new_max_serial =
        ($max_serial == 4294967295)
            ? 1
            : $max_serial + 1;
    $changeset->{'last_serial_number'} = $new_max_serial;
    my $encoded = $changeset->serialise_json();
    write_file("$data_dir/changeset_${new_max_serial}.json",
               $encoded);

    my $state;
    my $ss_path = "$data_dir/snapshot.json";
    my $has_snapshot = -e $ss_path;
    if ($has_snapshot) {
	my $data = read_file($ss_path);
	$state =
	    APNIC::RPKI::RTR::State->deserialise_json($data);
    } else {
        $state = APNIC::RPKI::RTR::State->new(session_id => 1);
    }
    my $error_pdu = $state->apply_changeset($changeset, 0, 1);

    my $new_encoded = $state->serialise_json();
    write_file("$data_dir/snapshot.json", $new_encoded);

    return 1;
}

1;
