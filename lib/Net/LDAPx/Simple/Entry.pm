package Net::LDAPx::Simple::Entry;

use strict;
use warnings;

our $AUTOLOAD;

use base qw( Class::ErrorHandler );

sub new {
    my ( $class, $c, $entry ) = @_;

    my $self = {
        entry   => $entry,
        context => $c,
    };

    bless $self, $class;
    return $self;
}

sub update {
    my ( $self, $args ) = @_;

    my %update = %$self;
    delete $update{entry};
    delete $update{context};

    my $mesg = $self->{context}->{ldap}->modify( $self->dn, replace => \%update );

    if ( $mesg->code ) {
        return $self->error($mesg->error);
    }
    else {
        return 1;
    }
}

sub delete {
    my $self = shift;
    my $mesg = $self->{context}->{ldap}->delete( $self->dn );

    if ( $mesg->code ) {
        return $self->error($mesg->error);
    }
    else {
        return 1;
    }
}

sub AUTOLOAD {
     my ($self) = @_;
     my $func   = $AUTOLOAD;
     return if $func =~ /::DESTROY$/;

     my ($class,$method) = $func =~ /(.+)::(.+)$/;

     my $code   = sub {
         my $self = shift;

         if ( @_ ) {
             $self->{$method} = shift;
         }
         else {
             if ( $method eq 'dn' ) {
                 $self->{$method} = $self->{entry}->dn;
             }
             else {
                 $self->{$method} = $self->{entry}->get_value($method);
             }
         }
         return $self->{$method};
     };

     no strict 'refs';
     *{$func} = $code;
     goto &$code;
 }

1;
