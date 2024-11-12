package APNIC::RPKI::RTR::Client::Aggregator;

use warnings;
use strict;

use APNIC::RPKI::RTR::Client;
use APNIC::RPKI::RTR::Utils qw(dprint);

use Clone qw(clone);
use File::Slurp qw(read_file write_file);
use JSON::XS qw(encode_json decode_json);
use List::Util qw(min);

sub new
{
    my $class = shift;
    my %args = @_;

    my $clients = $args{'clients'};
    if (not $clients) {
        die "Client list must be provided.";
    }
    if (not @{$clients}) {
        die "At least one client must be provided.";
    }

    for my $client (@{$clients}) {
        my $ref = ref $client;
        if (not $ref or $ref ne 'ARRAY') {
            die "Client entry is invalid.";
        }
        my ($index, $path) = @{$client};
        if ($index !~ /^\d+$/) {
            die "Client entry index is invalid.";
        }
        # Confirming that the data is valid.
        my $data = read_file($path);
        my $client_object =
            APNIC::RPKI::RTR::Client->deserialise_json($data);
    }

    my $min_index = min map { $_->[0] } @{$clients};

    my @sorted_clients =
        sort { $a->[0] <=> $b->[0] }
            @{$clients};

    my $self = {
        clients => \@sorted_clients,
        active  => $min_index,
    };

    bless $self, $class;
    return $self;
}

sub get_client_objects
{
    my ($self) = @_;

    my $clients = $self->{'clients'};
    my %by_index =
        map { $_->[0] => [] }
            @{$clients};
    for my $client (@{$clients}) {
        my ($index, $path) = @{$client};
        my $data = read_file($path);
        my $client_object =
            APNIC::RPKI::RTR::Client->deserialise_json($data);
        $client_object->{'path'} = $path;
        push @{$by_index{$index}}, $client_object;
    }

    return \%by_index;
}

sub save_client_object
{
    my ($self, $client) = @_;

    my $path = $client->{'path'};
    my $data = $client->serialise_json();
    write_file($path, $data);

    return 1;
}

sub reset
{
    my ($self, $force, $from_top) = @_;

    my $by_index = $self->get_client_objects();
    my $active   = $self->{'active'};

    if ((not defined $active) or $from_top) {
        $active = min keys %{$by_index};
        $self->{'active'} = $active;
    }

    my $success = 1;
    for my $client_object (@{$by_index->{$active}}) {
        eval { $client_object->reset($force) };
        if (my $error = $@) {
            dprint("Unable to reset client: $error");
            $success = 0;
            last;
        }
        $self->save_client_object($client_object);
    }

    if (not $success) {
        my @other_indexes =
            grep { $_ != $active }
                sort keys %{$by_index};
        for my $index (@other_indexes) {
            $success = 1;
            for my $client_object (@{$by_index->{$index}}) {
                eval { $client_object->reset($force) };
                if (my $error = $@) {
                    dprint("Unable to reset client: $error");
                    $success = 0;
                    last;
                }
                $self->save_client_object($client_object);
            }
            if ($success) {
                dprint("New active index is $index");
                $self->{'active'} = $index;
            }
        }
    }

    if (not $success) {
        $self->{'active'} = undef;
        die "Unable to reset any client set";
    }

    return 1;
}

sub refresh
{
    my ($self, $force) = @_;

    my $by_index = $self->get_client_objects();
    my $active   = $self->{'active'};

    if (not defined $active) {
        $active = min keys %{$by_index};
        $self->{'active'} = $active;
    }

    my $success = 1;
    for my $client_object (@{$by_index->{$active}}) {
        eval { $client_object->refresh($force) };
        if (my $error = $@) {
            dprint("Unable to refresh client: $error");
            $success = 0;
            last;
        }
        $self->save_client_object($client_object);
    }

    if (not $success) {
        my @other_indexes =
            grep { $_ != $active }
                sort keys %{$by_index};
        for my $index (@other_indexes) {
            $success = 1;
            for my $client_object (@{$by_index->{$index}}) {
                eval { $client_object->refresh($force) };
                if (my $error = $@) {
                    dprint("Unable to refresh client: $error");
                    $success = 0;
                    last;
                }
                $self->save_client_object($client_object);
            }
            if ($success) {
                dprint("New active index is $index");
                $self->{'active'} = $index;
            }
        }
    }

    if (not $success) {
        $self->{'active'} = undef;
        die "Unable to refresh any client set";
    }

    return 1;
}

sub state
{
    my ($self) = @_;
     
    my $by_index = $self->get_client_objects();
    my $active   = $self->{'active'};
    
    my @client_objects = @{$by_index->{$active}};
    my @states = map { clone($_->state()) } @client_objects;

    my $initial_state = shift @states;
    for my $other_state (@states) {
        $initial_state->apply_changeset(
            $other_state->to_changeset(),
            # Ignored anyway, because it's only relevant to error
            # PDUs.
            0,
            1,
            1
        );
    }

    return $initial_state;
}

sub serialise_json
{
    my ($self) = @_;

    my $data = {
        (map {
            $self->{$_} ? ($_ => $self->{$_}->serialise_json()) : ()
        } qw(state)),
        (map {
            $self->{$_} ? ($_ => $self->{$_}) : ()
        } qw(active clients))
    };

    return encode_json($data);
}

sub deserialise_json
{
    my ($class, $data) = @_;

    my $obj = decode_json($data);
    if ($obj->{'state'}) {
        $obj->{'state'} =
            APNIC::RPKI::RTR::State->deserialise_json($obj->{'state'});
    }
    bless $obj, $class;
    return $obj;
}

1;
