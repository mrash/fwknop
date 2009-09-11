# (X)Emacs mode: -*- cperl -*-

# This file is preprocessed by cmmg.pl .  Subs are sought, as 'sub name {' (at
# a line begin) until '}' at a line begin.  Optional POD documentation may
# precede, if started with =head (and ended with =cut).  Blank lines &
# comments in between will be silently ignored, and anything else will be
# noisily ignored.

# -------------------------------------

=head1 NAME

Class::Method::hash - Create methods for handling a hash value.

=head1 SYNOPSIS

  use Class::MethodMaker
    [ hash => [qw/ x /] ];

  $instance->x;                 # empty
  $instance->x(a => 1, b => 2, c => 3);
  $instance->x_count == 3;      # true
  $instance->x = (b => 5, d => 8); # Note this *replaces* the hash,
                                   # not adds to it
  $instance->x_index('b') == 5; # true
  $instance->x_exists('c');     # false
  $instance->x_exists('d');     # true

=head1 DESCRIPTION

Creates methods to handle hash values in an object.  For a component named
C<x>, by default creates methods C<x>, C<x_reset>, C<x_clear>, C<x_isset>,
C<x_count>, C<x_index>, C<x_keys>, C<x_values>, C<x_each>, C<x_exists>,
C<x_delete>, C<x_set>, C<x_get>.

=cut

sub hash {
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
    croak("Cannot specify both default & default_ctor options to hash ",
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
  my %names = map {; $_ => undef } qw( * *_set *_reset *_index *_each );
  # The newer '*' treats a single +{} differently.  This is needed to ensure
  # that hash_init works for v1 scenarios
  $names{'='} = '*_v1compat' if $options->{v1_compat};

  return {

=pod

Methods available are:

=cut

=pod

=head3 C<*>

I<Created by default>.  This method returns the list of keys and values stored
in the slot (they are returned pairwise, i.e., key, value, key, value; as with
perl hashes, no order of keys is guaranteed).  If any arguments are provided
to this method, they B<replace> the current hash contents.  In an array
context it returns the keys, values as an array and in a scalar context as a
hash-reference.  Note that this reference is no longer a direct reference to
the storage, in contrast to Class::MethodMaker v1.  This is to protect
encapsulation.  See x_ref if you need that functionality (and are prepared to
take the associated risk.)

If a single argument is provided that is an arrayref or hashref, it is
expanded and its contents used in place of the existing contents.  This is a
more efficient passing mechanism for large numbers of values.

=cut

          '*'        =>
          sub : method {
            my $want = wantarray;
            print STDERR "W: ", $want, ':', join(',',@_),"\n"
              if DEBUG;
            # We also deliberately avoid instantiating storage if not
            # necessary.
            if ( @_ == 1 ) {
              if ( exists %%STORAGE%% ) {
                return
                  unless defined $want;
                if ( $want ) {
                  %{%%STORAGE%%};
                } else {
                  +{%{%%STORAGE%%}};                        %%V2ONLY%%
                  %%STORAGE%%;                              %%V1COMPAT%%
                }
              } else {
                return
                  unless defined $want;
                if ( $want ) {
                  ();
                } else {
                  +{};
                }
              }
            } elsif ( @_ == 2 and ref $_[1] eq 'HASH') {
              %%STORE(+{%{$_[1]}},$v)%%
              # Only asgn-check the potential *values*
              %%ASGNCHK%(%%IFSTORE(values %$v, values %{$_[1]})%%)%%
              if ( ! defined $want ) {
                %{%%STORAGE%%} = %%IFSTORE(%$v,%{$_[1]})%%;
                return;
              }
  
              if ( $want ) {
                (%{%%STORAGE%%} = %%IFSTORE(%$v,%{$_[1]})%%);
              } else {
                +{%{%%STORAGE%%} = %%IFSTORE(%$v,%{$_[1]})%%}; %%V2ONLY%%
                %%V1COMPAT_ON%%
                %{%%STORAGE%%} = %%IFSTORE(%$v,%{$_[1]})%%;
                %%STORAGE%%;
                %%V1COMPAT_OFF%%
              }
            } else {
              croak "Uneven number of arguments to method '$names{'*'}'\n"
                unless @_ % 2;

              %%STORE(+{@_[1..$#_]},$v)%%
              # Only asgn-check the potential *values*
              %%ASGNCHK%(%%IFSTORE(values %$v, @_[map $_*2,1..($#_/2)])%%)%%
              if ( ! defined $want ) {
                %{%%STORAGE%%} = %%IFSTORE(%$v,@_[1..$#_])%%;
                return;
              }

              if ( $want ) {
                (%{%%STORAGE%%} = %%IFSTORE(%$v,@_[1..$#_])%%);
              } else {
                +{%{%%STORAGE%%} = %%IFSTORE(%$v,@_[1..$#_])%%}; %%V2ONLY%%
                %%V1COMPAT_ON%%
                %{%%STORAGE%%} = %%IFSTORE(%$v,@_[1..$#_])%%;
                %%STORAGE%%;
                %%V1COMPAT_OFF%%
              }
            }
          },

          #
          # This method is for internal use only.  It exists only for v1
          # compatibility, and may change or go away at any time.  Caveat
          # Emptor.
          #

          '!*_v1compat' =>
          sub : method {
            my $want = wantarray;

            if ( @_ == 1 ) {
              # No args
              return
                unless defined $want;
              %%STORAGE%% = +{}
                unless exists %%STORAGE%%;
              return $want ? %{%%STORAGE%%} : %%STORAGE%%;
            } elsif ( @_ == 2 ) {
              # 1 arg
              if ( my $type = ref $_[1] ) {
                if ( $type eq 'ARRAY' ) {
                  my $x = $names{'*_index'};
                  return my @x = $_[0]->$x(@{$_[1]});
                } elsif ( $type eq 'HASH' ) {
                  my $x = $names{'*_set'};
                  $_[0]->$x(%{$_[1]});
                  return $want ? %{%%STORAGE%%} : %%STORAGE%%;
                } else {
                  # Not a recognized ref type for hash method
                  # Assume it's an object type, for use with some tied hash
                  $x = $names{'*_index'};
                  return ($_[0]->$x($_[1]))[0];
                }
              } else { # $key is simple scalar
                $x = $names{'*_index'};
                return ($_[0]->$x($_[1]))[0];
              }
            } else {
              # Many args
              unless ( @_ % 2 ) {
                carp "No value for key '$_[-1]'.";
                push @_, undef;
              }
              my $x = $names{'*_set'};
              $_[0]->$x(@_[1..$#_]);
              $x = $names{'*'};
              return $want ? %{%%STORAGE%%} : %%STORAGE%%;
            }
          },

=pod

=head3 C<*_reset>

I<Created by default>.  Called without an argument, this resets the component
as a whole; deleting any associated storage, and returning the component to
its default state.  Normally, this means that I<*_isset> will return false,
and I<*> will return undef.  If C<-default> is in effect, then the component
will be set to the default value, and I<*_isset> will return true.  If
C<-default_ctor> is in effect, then the default subr will be invoked, and its
return value used to set the value of the component, and I<*_isset> will
return true.

If called with arguments, these arguments are treated as indexes into the
component, and the individual elements thus referenced are reset (their
storage deleted, so that I<*_isset(n)> will return false for appropriate I<n>,
except where C<-default> or C<-default_ctor> are in force, as above).  As with
perl arrays, resetting the highest set value implicitly decreases the count
(but x_reset(n) never unsets the aggregate itself, even if all the elements
are not set).

=cut

          '*_reset'  =>
          sub : method {
            if ( @_ == 1 ) {
              %%RESET%%%
              delete %%STORAGE%%;
            } else {
              delete @{%%STORAGE%%}{@_[1..$#_]};
            }
            return;
          },

=pod

=head3 C<*_clear>

I<Created by default>.  Empty the component of all elements, but without
deleting the storage itself.

If given a list of keys, then the elements I<that exist> indexed by those keys
are set to undef (but not deleted).

Note the very different semantics: C<< $x->a_clear('b') >> sets the value of
C<b> in component 'a' to undef (if C<b>) already exists (so C<<
$x->a_isset('b')) >> returns true), but C<< $x->a_clear() >> deletes the
element C<b> from component 'a' (so C<< $x->a_isset('b')) >> returns false).

=cut

          '*_clear'  =>
          sub : method {
            if ( @_ == 1 ) {
              %{%%STORAGE%%} = ();
            } else {
              ${%%STORAGE%%}{$_} = undef
                for grep exists ${%%STORAGE%%}{$_}, @_[1..$#_];
            }
            return;
          },

=pod

=head3 C<*_isset>

I<Created by default>.  Whether the component is currently set.  This is
different from being defined; initially, the component is not set (and if
read, will return undef); it can be set to undef (which is a set value, which
also returns undef).  Having been set, the only way to unset the component is
with C<*_reset>.

If a default value is in effect, then C<*_isset> will always return true.

I<*_isset()> tests the component as a whole.  I<*_isset(a)> tests the element
indexed by I<a>.  I<*_isset(a,b)> tests the elements indexed by I<a>, I<b>,
and returns the logical conjunction (I<and>) of the tests.

=cut

          '*_isset'  =>
          ( $default_defined      ?
            sub : method { 1 }    :
            sub : method {
              if ( @_ == 1 ) {
               exists %%STORAGE%%
             } elsif ( @_ == 2 ) {
               exists %%STORAGE%%->{$_[1]}
             } else {
               for ( @_[1..$#_] ) {
                 return
                   if ! exists %%STORAGE%%->{$_};
               }
               return 1;
             }
            }
          ),

=pod

=head3 C<*_count>

I<Created by default>.  Returns the number of elements in this component.
This is not affected by presence (or lack) of a C<default> (or
C<default_ctor>).  Returns C<undef> if whole component not set (as per
I<*_isset>).

=cut

           '*_count'  =>
           sub : method {
             if ( exists %%STORAGE%% ) {
               return scalar keys %{%%STORAGE%%};
             } else {
               return;
             }
           },

=pod

=head3 C<*_index>

I<Created by default>.  Takes a list of indices, returns a list of the
corresponding values.

If a default (or a default ctor) is in force, then a lookup by
index will vivify & set to the default the respective elements (and
therefore the aggregate data-structure also, if it's not already).

=cut

           # I did try to do clever things with returning refs if given refs,
           # but that conflicts with the use of lvalues
           '*_index' =>
           ( $default_defined      ?
             sub : method {
               for (@_[1..$#_]) {
                 %%DEFCHECK%(%%STORAGE%%->{$_})%%
               }
               @{%%STORAGE%%}{@_[1..$#_]};
             }                     :
             sub : method {
               @{%%STORAGE%%}{@_[1..$#_]};
             }
           ),

=pod

=head3 C<*_keys>

I<Created by default>.  The known keys, as a list in list context, as an
arrayref in scalar context.

If you're expecting a count of the keys in scalar context, see I<*_count>.

=cut

           '*_keys' =>
           sub : method {
             # Unusual ! wantarray order required because ?: supplies a scalar
             # context to it's middle argument.
             return ! wantarray ? [keys %{%%STORAGE%%}] : keys %{%%STORAGE%%};
           },

=pod

=head3 C<*_values>

I<Created by default>.  The known values, as a list in list context, as an
arrayref in scalar context.

=cut

           '*_values' =>
           sub : method {
             # Unusual ! wantarray order required because ?: supplies a scalar
             # context to it's middle argument.
             return
               ! wantarray ? [values %{%%STORAGE%%}] : values %{%%STORAGE%%};
           },

=pod

=head3 C<*_each>

I<Created by default>.  The next pair of key, value (as a list) from the hash.

=cut

           '*_each' =>
           sub : method {
             return each %{%%STORAGE%%};
           },

=pod

=head3 C<*_exists>

I<Created by default>.  Takes any number of arguments, considers each as a
key, and determines whether the key exists in the has.  Returns the logical
conjunction (I<and>).

=cut

           '*_exists' =>
           sub : method {
             return
               for grep ! exists  %%STORAGE%%->{$_}, @_[1..$#_];
             return 1;
           },

=pod

=head3 C<*_delete>

I<Created by default>.  This operates exactly like I<*_reset>, except that
calling this with no args does nothing.  This is provided for orthogonality
with the Perl C<delete> operator, while I<*_reset> is provided for
orthogonality with other component types.

=cut
           '*_delete' =>
           sub : method {
             if ( @_ > 1 ) {
               my $x = $names{'*_reset'};
               $_[0]->$x(@_[1..$#_]);
             }
             return;
           },


=pod

=head3 C<*_set>

  %n = $x->h; # (a=>1,b=>2,c=>3) (in some order)
  $h->h_set(b=>4,d=>7);
  %n = $h->a; # (a=>1,b=>4,c=>3,d=>7) (in some order)

I<Created by default>.  Takes a list, treated as pairs of index => value; each
given index is set to the corresponding value.  No return.

If two arguments are given, of which the first is an arrayref, then it is
treated as a list of indices of which the second argument (which must also be
an arrayref) are the corresponding values.  Thus the following two commands
are equivalent:

  $x->a_set(b=>4,d=>7);
  $x->a_set(['b','d'],[4,7]);

=cut

           '*_set'   =>
           sub : method {
             croak
               sprintf("'%s' requires an even number of args (got %d)\n",
                       $names{'*_set'}, @_-1)
               unless @_ % 2;
             if ( @_ == 3 and ref $_[1] eq 'ARRAY' ) {
               %%STORE([@{$_[2]}], $v)%%
               %%ASGNCHK%(%%IFSTORE(@$v,@{$_[2]})%%)%%
               @{%%STORAGE%%}{@{$_[1]}} = %%IFSTORE(@$v,@{$_[2]})%%;
             } else {
               %%STORE([@_[map {$_*2} 1..($#_/2)]], $v)%%
               %%ASGNCHK%(%%IFSTORE(@$v,@_[map {$_*2} 1..($#_/2)])%%)%%
               ${%%STORAGE%%}{$_[$_*2-1]} = %%IFSTORE($v->[$_-1], $_[$_*2])%%
                 for 1..($#_/2);
             }
             return;
           },

=pod

=head3 C<*_get>

I<Created by default>.  Retrieves the value of the component without setting
(ignores any arguments passed).

=cut

           '*_get'   =>
           sub : method {
             my $x = $names{'*'};
             return $_[0]->$x();
           },

           #
           # This method is deprecated.  It exists only for v1 compatibility,
           # and may change or go away at any time.  Caveat Emptor.
           #

           '!*_tally' =>
           sub : method {
             my @v;
             my ($y, $z) = @names{qw(*_set *_index)};

             for (@_[1..$#_]) {
               my $v = $_[0]->$z($_);
               $v++;
               $_[0]->$y($_, $v);
               push @v, $v;
             }
             return @v;
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
                    my %y = $_[0]->$x();
                    while ( my($k, $v) = each %y ) {
                      $y{$k} = $v->$f(@_[1..$#_])
                        if defined $v;
                    }
                    # Unusual ! wantarray order required because ?: supplies
                    # a scalar context to it's middle argument.
                    ! wantarray ? \%y : %y;
                  }
               } @forward),
         }, \%names;
}
