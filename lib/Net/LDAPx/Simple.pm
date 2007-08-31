package Net::LDAPx::Simple;

use warnings;
use strict;
use Carp;

use version;
our $VERSION = qv('0.0.1');

use base qw( Class::Accessor::Fast Class::ErrorHandler );
use Net::LDAP;
use Net::LDAPx::Simple::Context;
use Net::LDAPx::Simple::Entries;

sub new {
    my ( $class, $args ) = @_;

    my $self = {
        host    => $args->{host}    || 'localhost',
        port    => $args->{port}    || '389',
        bind_dn => $args->{bind_dn} || '',
        bind_pw => $args->{bind_pw} || '',
        base    => $args->{base}    || '',
    };

    my $c = Net::LDAPx::Simple::Context->new({
        ldap => Net::LDAP->new( $self->{host}, port => $self->{port} ),
    });

    $self->{context} = $c;
    $c->{ldap}->bind( $self->{bind_dn}, password => $self->{bind_pw} );

    bless $self, $class;
    return $self;
}

sub search {
    my ( $self, $args ) = @_;

    my $msg = $self->{context}->{ldap}->search(
        base   => $self->{base},
        filter => $self->_make_filter($args),
    );

    return Net::LDAPx::Simple::Entries->new($self->{context}, $msg);
}

sub auth {
    my ( $self, $args ) = @_;

    $args->{password} ||= $args->{userpassword};

    return $self->error('No password') unless defined $args->{password};

    my $entries = $self->search({ uid => $args->{uid} });

    if ( $entries->count > 1 ) {
        return $self->error('There are two or more entries');
    }

    my $entry = $entries->first;
    my $res = $self->bind({
        dn       => $entry->dn,
        password => $args->{password},
    });

    $self->bind({
        dn       => $self->{bind_dn},
        password => $self->{bind_pw},
    });

    return $res ? $entry : undef;
}

sub bind {
    my ( $self, $args ) = @_;

    my $mesg = $self->{context}->{ldap}->bind(
        $args->{dn},
        password => $args->{password},
    );

    if ( $mesg->code ) {
        return $self->error($mesg->error);
    }
    else {
        return 1;
    }
}

sub create {
    my ( $self, $args ) = @_;

    my $dn = delete $args->{dn};

    my $mesg = $self->{context}->{ldap}->add( $dn, attr => [ %$args ] );

    if ( $mesg->code ) {
        return $self->error($mesg->error);
    }
    else {
        use Data::Dumper;
        warn Dumper($mesg);
        return 1;
    }
}

sub _make_filter {
    local $^W = 0;  # really, you've gotta be fucking kidding me
    my $self  = shift;
    my $where = _anoncopy(shift);   # prevent destroying original
    my $ref   = ref $where || '';
    my $join  = shift || $self->{logic} ||
                    ( $ref eq 'ARRAY' ? '|' : '&' );

    # For assembling SQL fields and values
    my(@sqlf, @sqlv) = ();

    # If an arrayref, then we join each element
    if ($ref eq 'ARRAY') {
        # need to use while() so can shift() for arrays
        my $subjoin;
        while (my $el = shift @$where) {

            # skip empty elements, otherwise get invalid trailing AND stuff
            if (my $ref2 = ref $el) {
                if ($ref2 eq 'ARRAY') {
                    next unless @$el;
                } elsif ($ref2 eq 'HASH') {
                    next unless %$el;
                    $subjoin ||= '&';
                } elsif ($ref2 eq 'SCALAR') {
                    # literal SQL
                    push @sqlf, $$el;
                    next;
                }
                #$self->_debug("$ref2(*top) means join with $subjoin");
            } else {
                # top-level arrayref with scalars, recurse in pairs
                #$self->_debug("NOREF(*top) means join with $subjoin");
                $el = {$el => shift(@$where)};
            }
            my @ret = $self->_make_filter($el, $subjoin);
            push @sqlf, shift @ret;
            #push @sqlv, @ret;
        }
    }
    elsif ($ref eq 'HASH') {
        # Note: during recursion, the last element will always be a hashref,
        # since it needs to point a column => value. So this be the end.
        for my $k (sort keys %$where) {
            my $v = $where->{$k};
            #my $label = $self->_quote($k);
            my $label = $k;
            if ($k =~ /^-(\D+)/) {
                # special nesting, like -and, -or, -nest, so shift over
                my $subjoin = $self->_modlogic($1);
                #my $subjoin = $1 eq 'or' ? '|' : '&';
                #$self->_debug("OP(-$1) means special logic ($subjoin), recursing...");
                my @ret = $self->_make_filter($v, $subjoin);
                push @sqlf, shift @ret;
                push @sqlv, @ret;
            }
            #elsif (! defined($v)) {
            #    # undef = null
            #    $self->_debug("UNDEF($k) means IS NULL");
            #    push @sqlf, $label . $self->_sqlcase(' is null');
            #}
            elsif (ref $v eq 'ARRAY') {
                my @v = @$v;

                # multiple elements: multiple options
                #$self->_debug("ARRAY($k) means multiple elements: [ @v ]");

                # special nesting, like -and, -or, -nest, so shift over
                #my $subjoin = $self->_sqlcase('or');
                my $subjoin = '|';
                if ($v[0] =~ /^-(\D+)/) {
                    $subjoin = $self->_modlogic($1);    # override subjoin
                    #$subjoin = $1 eq 'or' ? '|' : '&';
                    #$self->_debug("OP(-$1) means special logic ($subjoin), shifting...");
                    shift @v;
                }

                # map into an array of hashrefs and recurse
                my @ret = $self->_make_filter([map { {$k => $_} } @v], $subjoin);

                # push results into our structure
                push @sqlf, shift @ret;
                push @sqlv, @ret;
            } elsif (ref $v eq 'HASH') {
                # modified operator { '!=', 'completed' }
                for my $f (sort keys %$v) {
                    my $x = $v->{$f};
                    #$self->_debug("HASH($k) means modified operator: { $f }");

                    # check for the operator being "IN" or "BETWEEN" or whatever
                    if (ref $x eq 'ARRAY') {
                          if ($f =~ /^-?\s*(not[\s_]+)?(in|between)\s*$/i) {
                              my $u = $self->_modlogic($1 . $2);
                              $self->_debug("HASH($f => $x) uses special operator: [ $u ]");
                              if ($u =~ /between/i) {
                                  # SQL sucks
                                  push @sqlf, join ' ', $self->_convert($label), $u, $self->_convert('?'),
                                                        $self->_sqlcase('and'), $self->_convert('?');
                              } else {
                                  push @sqlf, join ' ', $self->_convert($label), $u, '(',
                                                  join(', ', map { $self->_convert('?') } @$x),
                                              ')';
                              }
                              push @sqlv, $self->_bindtype($k, @$x);
                          } else {
                              # multiple elements: multiple options
                              #$self->_debug("ARRAY($x) means multiple elements: [ @$x ]");

                              # map into an array of hashrefs and recurse
                              my @ret = $self->_make_filter([map { {$k => {$f, $_}} } @$x]);

                              # push results into our structure
                              push @sqlf, shift @ret;
                              push @sqlv, @ret;
                          }
                    }
                    #elsif (! defined($x)) {
                    #    # undef = NOT null
                    #    my $not = ($f eq '!=' || $f eq 'not like') ? ' not' : '';
                    #    push @sqlf, $label . $self->_sqlcase(" is$not null");
                    #}
                    else {
                        # regular ol' value
                        $f =~ s/^-//;   # strip leading -like =>
                        $f =~ s/_/ /;   # _ => " "
                        #push @sqlf, join ' ', $self->_convert($label), $self->_sqlcase($f), $self->_convert('?');
                        my $not = $f eq '!=' ? '!' : '';
                        $f =~ s/^!//;
                        push @sqlf, {
                            not   => $not,
                            cmp   => $f,
                            label => $label,
                            value => $x,
                        };
                        #push @sqlv, $self->_bindtype($k, $x);
                    }
                }
            } elsif (ref $v eq 'SCALAR') {
                # literal SQL
                $self->_debug("SCALAR($k) means literal SQL: $$v");
                push @sqlf, "$label $$v";
            } else {
                # standard key => val
                #$self->_debug("NOREF($k) means simple key=val: $k $self->{cmp} $v");
                #push @sqlf, join ' ', $self->_convert($label), $self->_sqlcase($self->{cmp}), $self->_convert('?');
                $self->{cmp} = '=';
                push @sqlf, {
                    not   => '',
                    cmp   => $self->{cmp},
                    label => $label,
                    value => $v,
                };
                #push @sqlv, $self->_bindtype($k, $v);
            }
        }
    }
    elsif ($ref eq 'SCALAR') {
        # literal sql
        $self->_debug("SCALAR(*top) means literal SQL: $$where");
        push @sqlf, $$where;
    }
    elsif (defined $where) {
        # literal sql
        $self->_debug("NOREF(*top) means literal SQL: $where");
        push @sqlf, $where;
    }

    # assemble and return sql
    #my $wsql = @sqlf ? '( ' . join(" $join ", @sqlf) . ' )' : '';
    my $wsql = @sqlf > 1 ? '(' . $join . _make_cond(\@sqlf) .')'
             : @sqlf > 0 ? _make_cond(\@sqlf, $join)
             : '';

    #warn $wsql;
    return $wsql;
}

sub _make_cond {
    my $sqlf = shift;
    my $join = shift || '';

    my $filter;
    for ( @$sqlf ) {
        if ( ref $_ ) {
            $filter .= '(!' if $join eq '!';
            $filter .= '(' if $_->{not};
            $filter .= $_->{not} . '(' . $_->{label} . $_->{cmp} . $_->{value} . ')';
            $filter .= ')' if $_->{not};
            $filter .= ')' if $join eq '!';
        }
        else {
            $filter .= $_;
        }
    }

    return $filter;
}

sub _modlogic {
    my ( $self, $op ) = @_;
    my %logic = (
        and => '&',
        or  => '|',
        not => '!',
    );

    return $logic{$op} || '&';
}

sub _anoncopy {
    my $orig = shift;
    return (ref $orig eq 'HASH')  ? +{map { $_ => _anoncopy($orig->{$_}) } keys %$orig}
         : (ref $orig eq 'ARRAY') ? [map _anoncopy($_), @$orig]
         : $orig;
}


1;
__END__

=head1 NAME

Net::LDAPx::Simple - [One line description of module's purpose here]


=head1 VERSION

This document describes Net::LDAPx::Simple version 0.0.1


=head1 SYNOPSIS

    use Net::LDAPx::Simple;

=for author to fill in:
    Brief code example(s) here showing commonest usage(s).
    This section will be as far as many users bother reading
    so make it as educational and exeplary as possible.
  
  
=head1 DESCRIPTION

=for author to fill in:
    Write a full description of the module and its features here.
    Use subsections (=head2, =head3) as appropriate.


=head1 INTERFACE 

=for author to fill in:
    Write a separate section listing the public components of the modules
    interface. These normally consist of either subroutines that may be
    exported, or methods that may be called on objects belonging to the
    classes provided by the module.


=head1 DIAGNOSTICS

=for author to fill in:
    List every single error and warning message that the module can
    generate (even the ones that will "never happen"), with a full
    explanation of each problem, one or more likely causes, and any
    suggested remedies.

=over

=item C<< Error message here, perhaps with %s placeholders >>

[Description of error here]

=item C<< Another error message here >>

[Description of error here]

[Et cetera, et cetera]

=back


=head1 CONFIGURATION AND ENVIRONMENT

=for author to fill in:
    A full explanation of any configuration system(s) used by the
    module, including the names and locations of any configuration
    files, and the meaning of any environment variables or properties
    that can be set. These descriptions must also include details of any
    configuration language used.
  
Net::LDAPx::Simple requires no configuration files or environment variables.


=head1 DEPENDENCIES

=for author to fill in:
    A list of all the other modules that this module relies upon,
    including any restrictions on versions, and an indication whether
    the module is part of the standard Perl distribution, part of the
    module's distribution, or must be installed separately. ]

None.


=head1 INCOMPATIBILITIES

=for author to fill in:
    A list of any modules that this module cannot be used in conjunction
    with. This may be due to name conflicts in the interface, or
    competition for system or program resources, or due to internal
    limitations of Perl (for example, many modules that use source code
    filters are mutually incompatible).

None reported.


=head1 BUGS AND LIMITATIONS

=for author to fill in:
    A list of known problems with the module, together with some
    indication Whether they are likely to be fixed in an upcoming
    release. Also a list of restrictions on the features the module
    does provide: data types that cannot be handled, performance issues
    and the circumstances in which they may arise, practical
    limitations on the size of data sets, special cases that are not
    (yet) handled, etc.

No bugs have been reported.

Please report any bugs or feature requests to
C<bug-net-ldapx-simple@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.


=head1 AUTHOR

Gosuke Miyashita  C<< <gosukenator@gmail.com> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007, Gosuke Miyashita C<< <gosukenator@gmail.com> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.
