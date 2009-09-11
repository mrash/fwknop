# (X)Emacs mode: -*- cperl -*-

# This file is preprocessed by cmmg.pl .  Subs are sought, as 'sub name {' (at
# a line begin) until '}' at a line begin.  Optional POD documentation may
# precede, if started with =head (and ended with =cut).  Blank lines &
# comments in between will be silently ignored, and anything else will be
# noisily ignored.

# -------------------------------------

=head1 NAME

Class::Method::array - Create methods for handling an array value.

=head1 SYNOPSIS

  use Class::MethodMaker
    [ array => [qw/ x /] ];

  $instance->x;                # empty
  $instance->x(1, 1, 2, 3, 5, 8);
  $instance->x_count == 6;     # true
  $instance->x = (13, 21, 34);
  $instance->x_index(1) == 21; # true

=head1 DESCRIPTION

Creates methods to handle array values in an object.  For a component named
C<x>, by default creates methods C<x>, C<x_reset>, C<x_clear>, C<x_isset>,
C<x_count>, C<x_index>, C<x_push>, C<x_pop>, C<x_unshift>, C<x_shift>,
C<x_splice>.

=cut

# Sentinel value to tell array to clear.  Note that by being a reference,
# reconstructing it elsewhere won't work: so passing in a normal reference to
# 1 will store that reference to one, as expected.  \undef strangely doesn't
# work.

sub array {
  my $SENTINEL_CLEAR = \1;
  my $class  = shift;
  my ($target_class, $name, $options, $global) = @_;

  my %known_options = map {; $_ => 1 } qw( static type forward
                                           default default_ctor
                                           tie_class tie_args
                                           read_cb store_cb
                                           v1_compat );
  if ( my @bad_opt = grep ! exists $known_options{$_}, keys %$options ) {
    my $prefix = 'Option' . (@bad_opt > 1 ? 's' : '');
    croak("$prefix not recognized for attribute type hash: ",
          join(', ', @bad_opt), "\n");
  }

  my $type = $options->{type};
  croak "argument to -type ($type) must be a simple value\n"
    unless ! ref $type;

  my $forward = $options->{forward};
  my @forward;
  if ( defined $forward ) {
    if ( ref $forward ) {
      croak("-forward option can only handle arrayrefs or simple values " .
            "($forward)\n")
        unless UNIVERSAL::isa($forward, 'ARRAY');
      @forward = @$forward;
      print "Value '$_' passed to -forward is not a simple value"
        for grep ref($_), @forward;
    } else {
      @forward = $forward;
    }
  }

  my ($default, $dctor, $default_defined);
  if ( exists $options->{default} ) {
    croak("Cannot specify both default & default_ctor options to array ",
          "(attribute $name\n")
      if exists $options->{default_ctor};
    $default = $options->{default};
    $default_defined = 1;
  } elsif ( exists $options->{default_ctor} ) {
    if ( ! ref $options->{default_ctor} ) {
      my $meth = $options->{default_ctor};
      croak("default_ctor can only be a simple value when -type is in effect",
            " (attribute $name)\n")
        unless defined $type;
      croak("default_ctor must be a valid identifier (or a code ref): $meth ",
            "(attribute $name)\n")
        unless $meth =~ /^[A-Za-z_][A-Za-z0-9_]*/;
      $dctor = sub { $type->$meth(@_) };
    } else {
      $dctor = $options->{default_ctor};
      croak("Argument to default_ctor must be a simple value or a code ref ",
            " (attribute $name)\n")
        if ! UNIVERSAL::isa($dctor, 'CODE');
    }
    $default_defined = 1;
  }

  my ($tie_class, @tie_args);
  if ( exists $options->{tie_class} ) {
    $tie_class =  $options->{tie_class};
    if ( exists $options->{tie_args} ) {
      my $tie_args =  $options->{tie_args};
      @tie_args = ref $tie_args ? @$tie_args : $tie_args;
    }
  } elsif ( exists $options->{tie_args} ) {
    carp "tie_args option ignored in absence of tie_class(attribute $name)\n";
  }

  # callback options
  my @read_callbacks = ref $options->{read_cb} eq 'ARRAY' ?
                        @{$options->{read_cb}}            :
                        $options->{read_cb}
    if exists $options->{read_cb};
  my @store_callbacks = ref $options->{store_cb} eq 'ARRAY' ?
                        @{$options->{store_cb}}             :
                        $options->{store_cb}
    if exists $options->{store_cb};

  %%STORDECL%%

  # Predefine keys for subs we always want to exist (because they're
  # referenced by other subs)
  my %names = map {; $_ => undef } qw( * *_reset *_index );

  return {

=pod

Methods available are:

=head3 C<*>

I<Created by default.> This method returns the list of values stored in the
slot.  If any arguments are provided to this method, they B<replace> the
current list contents.  In an array context it returns the values as an array
and in a scalar context as a reference to an array.  Note that this reference
is no longer a direct reference to the storage, in contrast to
Class::MethodMaker v1.  This is to protect encapsulation.  See x_ref if you
need that functionality (and are prepared to take the associated risk.)  This
function no longer auto-expands arrayrefs input as arguments, since that makes
it awkward to set individual values to arrayrefs.  See x_setref for that
functionality.

If a default value is in force, then that value will be auto-vivified (and
therefore set) for each otherwise I<unset> (not I<not defined>) value up to
the array max (so new items will not be appended)

=cut

          '*'        =>
          sub : method {
            my $want = wantarray;
            print STDERR "W: ", $want, ':', join(',',@_),"\n"
              if DEBUG;

            # We also deliberately avoid instantiating storage if not
            # necessary.

            if ( @_ == 1 ) {
              %%DEFAULT_ON%%
              if ( exists %%STORAGE%% ) {
                for (0..$#{%%STORAGE%%}) {
                  %%DEFCHECK@(%%STORAGE%%->[$_])%%;
                }
              }
              %%DEFAULT_OFF%%

              if ( exists %%STORAGE%% ) {
                if ( ! defined $want ) {
                  return;
                } elsif ( $want ) {
                  return @{%%STORAGE%%};
                } else {
                  return [@{%%STORAGE%%}];
                }
              } else {
                if ( ! defined $want ) {
                  return;
                } elsif ( $want ) {
                  return ();
                } else {
                  return [];
                }
              }
            } else {
              {
                no warnings "numeric";
                $#_ = 0
                  if $#_ and defined $_[1] and $_[1] == $SENTINEL_CLEAR;
              }

              my @x;
              %%V1COMPAT_ON%%
              if ( $options->{tie_class} ) {
                @x = @_[1..$#_];
              } else {
                @x = map { ref $_ eq 'ARRAY' ? @$_ : ($_) } @_[1..$#_];
              }
              %%V1COMPAT_OFF%%

              %%V2ONLY_ON%%
              @x = @_[1..$#_];
              %%V2ONLY_OFF%%

              %%STORE(\@x, $v)%%
              %%ASGNCHK@(%%IFSTORE(@$v,@x)%%)%%
              if ( ! defined $want ) {
                @{%%STORAGE%%} = %%IFSTORE(@$v,@x)%%;
                return;
              } elsif ( $want ) {
                @{%%STORAGE%%} = %%IFSTORE(@$v,@x)%%;
              } else {
                [@{%%STORAGE%%} = %%IFSTORE(@$v,@x)%%];
              }
            }
          },

=pod

=head3 C<*_reset>

I<Created by default.> Called without an argument, this resets the component
as a whole; deleting any associated storage, and returning the component to
its default state.  Normally, this means that C<*_isset> will return false,
and C<*> will return undef.  If C<-default> is in effect, then the component
will be set to the default value, and C<*_isset> will return true.  If
C<-default_ctor> is in effect, then the default subr will be invoked, and its
return value used to set the value of the component, and C<*_isset> will
return true.

If called with arguments, these arguments are treated as indexes into the
component, and the individual elements thus referenced are reset (their
storage deleted, so that C<*_isset(n)> will return false for appropriate I<n>,
except where C<-default> or C<-default_ctor> are in force, as above).  As with
perl arrays, resetting the highest set value implicitly decreases the count
(but x_reset(n) never unsets the aggregate itself, even if all the elements
are not set).

=cut

          '*_reset'  =>
          sub : method {
            if ( @_ == 1 ) {
              %%RESET@%%
              delete %%STORAGE%%;
            } else {
              delete @{%%STORAGE%%}[@_[1..$#_]];
            }
            return;
          },


=pod

=head3 C<*_clear>

  package MyClass;
  use Class::MethodMaker
    [ scalar => [{'*_clear' => '*_clear'}, 'a'],
      new    => new, ];

  package main;
  my $m = MyClass->new;
  $m->a(5);
  $a = $m->a;       # 5
  $x = $m->a_isset; # true
  $m->a_clear;
  $a = $m->a;       # *undef*
  $x = $m->a_isset; # true

I<Created on request>.  A shorthand for setting to undef.  Note that the
component will be set to undef, not reset, so C<*_isset> will return true.

=cut

          '*_clear'  =>
           sub : method {
             my $x = $names{'*'};
             $_[0]->$x($SENTINEL_CLEAR);
             return;
           },

=pod

=head3 C<*_isset>

I<Created by default.> Whether the component is currently set.  This is
different from being defined; initially, the component is not set (and if
read, will return undef); it can be set to undef (which is a set value, which
also returns undef).  Having been set, the only way to unset the component is
with <*_reset>.

If a default value is in effect, then <*_isset> will always return true.

C<*_isset()> tests the component as a whole.  C<*_isset(a)> tests the element
indexed by I<a>.  C<*_isset(a,b)> tests the elements indexed by I<a>, I<b>,
and returns the logical conjunction (I<and>) of the tests.

=cut

          '*_isset'  =>
          ( $default_defined      ?
            sub : method { 1 }    :
            sub : method {
              if ( @_ == 1 ) {
               exists %%STORAGE%%
             } elsif ( @_ == 2 ) {
               exists %%STORAGE%%->[$_[1]]
             } else {
               return
                 for grep ! exists %%STORAGE%%->[$_], @_[1..$#_];
               return 1;
             }
            }
          ),

=pod

=head3 C<*_count>

I<Created by default.> Returns the number of elements in this component.  This
is not affected by presence (or lack) of a C<default> (or C<default_ctor>).
Returns C<undef> if whole component not set (as per C<*_isset>).

=cut

           '*_count'  =>
           sub : method {
             if ( exists %%STORAGE%% ) {
               return scalar @{%%STORAGE%%};
             } else {
               return;                            %%V2ONLY%%
               return 0;                          %%V1COMPAT%%
             }
           },

=pod

=head3 C<*_index>

I<Created by default.> Takes a list of indices, returns a list of the
corresponding values.

If a default (or a default ctor) is in force, then a lookup by
index will vivify & set to the default the respective elements (and
therefore the aggregate data-structure also, if it's not already).

Beware of a bug in perl 5.6.1 that will sometimes invent values in
previously unset slots of arrays that previously contained a value.
So, vivifying a value (e.g. by x_index(2)) where x_index(1) was
previously unset might cause x_index(1) to be set spuriously.  This
is fixed in 5.8.0.

=cut

           # I did try to do clever things with returning refs if given refs,
           # but that conflicts with the use of lvalues
           '*_index' =>
           ( $default_defined      ?
             sub : method {
               for (@_[1..$#_]) {
                 %%DEFCHECK@(%%STORAGE%%->[$_])%%
               }
               @{%%STORAGE%%}[@_[1..$#_]];
             }                     :
             sub : method {
               @{%%STORAGE%%}[@_[1..$#_]];
             }
           ),

=pod

=head3 C<*_push>

I<Created by default.> Push item(s) onto the end of the list.  No return
value.

=cut

           '*_push' =>
           sub : method {
             %%ASGNCHK@(@_[1..$#_])%%
             push @{%%STORAGE%%}, @_[1..$#_];
             return;                                        %%V2ONLY%%
           },

=pod

=head3 C<*_pop>

I<Created by default.> Given a number, pops that many items off the end of the
list, and returns them (as a ref in scalar context, as a list in list
context).  Without an arg, always returns a single element.  Given a number,
returns them in array order (not in reverse order as multiple pops would).

=cut

           '*_pop' =>
           sub : method {
             if ( @_ == 1 ) {
               pop @{%%STORAGE%%};
             } else {
               return
                 unless defined wantarray;
               ! wantarray ? [splice @{%%STORAGE%%}, -$_[1]] :
                              splice @{%%STORAGE%%}, -$_[1] ;
             }
           },

=pod

=head3 C<*_unshift>

I<Created by default.> Push item(s) onto the start of the list.  No return
value.

=cut

           '*_unshift' =>
           sub : method {
             %%ASGNCHK@(@_[1..$#_])%%
             unshift @{%%STORAGE%%}, @_[1..$#_];
             return;                                        %%V2ONLY%%
           },

=pod

=head3 C<*_shift>

I<Created by default.> Given a number, shifts that many items off the start of
the list, and returns them (as a ref in scalar context, as a list in list
context).  Without an arg, always returns a single element.  Given a number,
returns them in array order.

=cut

           '*_shift' =>
           sub : method {
             if ( @_ == 1 ) {
               shift @{%%STORAGE%%};
             } else {
               splice @{%%STORAGE%%}, 0, $_[1], return
                 unless defined wantarray;
               ! wantarray ? [splice @{%%STORAGE%%}, 0, $_[1]] :
                              splice @{%%STORAGE%%}, 0, $_[1] ;
             }
           },

=pod

=head3 C<*_splice>

I<Created by default.> Arguments as for L<perldoc perlfunc splice|splice>.
Returns an arrayref in scalar context (even if a single item is spliced), and
a list in list context.

=cut

           '*_splice' =>
           sub : method {
             # Disturbing weirdness due to prototype of splice.
             #   splice @{%%STORAGE%%}, @_[1..$#_]
             # doesn't work because the prototype wants a scalar for
             # argument 2, so the @_[1..$#_] gets evaluated in a scalar
             # context, thus counts the elements of @_ (subtract 1).
             # Ripping of the head elements
             #   splice @{%%STORAGE%%}, $_[1], $_[2], @_[3..$#_]
             # almost works, but that the $_[2] if not present presents an
             # undef, which works as a zero, whereas
             #   splice @{%%STORAGE%%}, $_[1]
             # splices to the end of the array

             if ( @_ < 3 ) {
               if ( @_ < 2 ) {
                 $_[1] = 0;
               }
               $_[2] = @{%%STORAGE%%} - $_[1]
             }
             %%ASGNCHK@(@_[3..$#_])%%

             splice(@{%%STORAGE%%}, $_[1], $_[2], @_[3..$#_]), return
               unless defined wantarray;
             ! wantarray ? [splice(@{%%STORAGE%%}, $_[1], $_[2], @_[3..$#_])] :
                            splice(@{%%STORAGE%%}, $_[1], $_[2], @_[3..$#_])  ;
           },

=pod

=head3 C<*_get>

I<Created on request>.  Retrieves the value of the component without setting
(ignores any arguments passed).

=cut

           '!*_get'   =>
           sub : method {
             my $x = $names{'*'};
             return $_[0]->$x();
           },

=pod

=head3 C<*_set>

  @n = $x->a; # (1,2,3)
  $x->a_set(1=>4,3=>7);
  @n = $x->a; # (1,4,3,7)

I<Created by default.> Takes a list, treated as pairs of index => value; each
given index is set to the corresponding value.  No return.

If two arguments are given, of which the first is an arrayref, then it is
treated as a list of indices of which the second argument (which must also be
an arrayref) are the corresponding values.  Thus the following two commands
are equivalent:

  $x->a_set(1=>4,3=>7);
  $x->a_set([1,3],[4,7]);

=cut

           '*_set'   =>
           sub : method {
             if ( @_ == 3 and ref $_[1] eq 'ARRAY' ) {
               %%ASGNCHK@(@{$_[2]})%%
               @{%%STORAGE%%}[@{$_[1]}] = @{$_[2]};
             } else {
               croak
                 sprintf("'%s' requires an even number of args (got %d)\n",
                         $names{'*_set'}, @_-1)
                 unless @_ % 2;
               %%ASGNCHK@(@_[map $_*2,1..($#_/2)])%%
               ${%%STORAGE%%}[$_[$_*2-1]] = $_[$_*2]
                 for 1..($#_/2);
             }
             return;
           },

           #
           # This method is deprecated.  It exists only for v1 compatibility,
           # and may change or go away at any time.  Caveat Emptor.
           #

           '!*_ref'   =>
           sub : method { %%STORAGE%% },

           map({; my $f = $_;
                $_ =>
                  sub : method {
                    my $x = $names{'*'};
                    my @x;
                    my @y = $_[0]->$x();
                    @x = map +(defined $_ ? $_->$f(@_[1..$#_]) : undef), @y;
                    # We don't check for a undefined wantarray here, since
                    # calling this in a void context is a sufficiently
                    # nonsensical thing to do that checking for it is likely
                    # performance hit than the typical saving.
                    ! wantarray ? \@x : @x;
                  }
               } @forward),
         }, \%names;
}
