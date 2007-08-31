package Net::LDAPx::Simple::Entries;

use strict;
use warnings;

use Net::LDAPx::Simple::Entry;

sub new {
    my ( $class, $c, $msg ) = @_;

    my @entries;

    for my $entry ( $msg->entries ) {
        push @entries, Net::LDAPx::Simple::Entry->new($c, $entry);
    }

    my $self = {
        entries => \@entries,
        index   => 0,
        context => $c,
    };

    bless $self, $class;
    return $self;
}

sub next {
    my $self = shift;
    return $self->{entries}->[$self->{index}++];
}

sub first {
    my $self = shift;
    return $self->{entries}->[0];
}

sub count {
    my $self = shift;
    return scalar @{ $self->{entries} };
}

1;
