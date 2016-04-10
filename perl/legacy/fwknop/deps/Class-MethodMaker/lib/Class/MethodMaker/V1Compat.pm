# (X)Emacs mode: -*- cperl -*-

package Class::MethodMaker::V1Compat;

=head1 NAME

Class::MethodMaker::V1Compat - V1 compatibility code for C::MM

=head1 SYNOPSIS

This class is for internal implementation only.  It is not a public API.

=head1 DESCRIPTION

Class::MethodMaker version 2 strives for backward-compatiblity with version 1
as far as possible.  That is to say, classes built with version 1 should work
with few if any changes.  However, the calling conventions for building new
classes are significantly different: this is necessary to achieve a greater
consistency of arguments.

Version 2 takes all arguments within a single arrayref:

  use Class::MethodMaker
    [ scalar => 'a' ];

If arguments are presented as a list, then Class::MethodMaker assumes that
this is a version 1 call, and acts accordingly.  Version 1 arguments are
passed and internally rephrased to version 2 arguments, and passed off to the
version 2 engine.  Thus, the majority of version 1 calls can be upgraded to
version 2 merely by rephrasing.  However, there are a number of behaviours
that in version 1 that are internally inconsistent.  These behaviours are
mimicked in version 1 mode as far as possible, but are not reproducible in
version 2 (to allow version 2 clients to rely on a more internally consistent
interface).

=head2 Version 2 Implementations

The nearest equivalent to each 1 component (slot) available in version 2 is
shown below using the indicated data-structures & options to create a
component called C<a> that mimicks the V1 component behaviour as closely as
possible:

=over 4

=item abstract

  use Class::MethodMaker
    [ abstract => 'a' ];

=item boolean

Boolean is available as a backwards compatibility hack, but there is currently
no V2 equivalent.  It is likely that some replacement mechanism will be
introduced in the future, but that it will be incompatible with the version 1
boolean.

=item code

  use Class::MethodMaker
    [ scalar => 'a' ];

Let's face it, the v1 store-if-it's-a-coderef-else-retrieve semantics are
rather broken.  How do you pass a coderef as argument to one of these?  It is
on the TODO list to recognize code as fundamental restricted type (analogous
to INTEGER), which would add in a C<*_invoke> method.

=item copy

  use Class::MethodMaker
    [ copy => 'a' ];

The v2 method is the same as v1.

=item counter

  use Class::MethodMaker
    [ scalar => [{-type => Class::MethodMaker::Constants::INTEGER}, 'a'] ];

=item copy

=item deep_copy

  use Class::MethodMaker
    [ copy => [ -deep => 'a' ] ];

=item get_concat

  use Class::MethodMaker
    [ scalar => [{ -store_cb => sub {
                                  defined $_[1] ? ( defined $_[3] ?
                                                    "$_[3] $_[1]" : $_[1] )
                                                : undef;
                                }
                 },
                 'a' ]
    ];

=item get_set

  use Class::MethodMaker
    [ scalar => 'a' ];

=item hash

  use Class::MethodMaker
    [ hash => 'a' ];

=item key_attrib

Although v1 calls will continue to work, this is not supported in v2.

=item key_with_create

Although v1 calls will continue to work, this is not supported in v2.

=item list

  use Class::MethodMaker
    [ list => 'a' ];

Note that the C<*> method now I<sets> the whole array if given arguments.

=item method

See C<code>.

=item new

  use Class::MethodMaker
    [ new => 'a' ];

=item new_hash_init

  use Class::MethodMaker
    [ new => [ -hash => 'a' ] ];

=item new_hash_with_init

  use Class::MethodMaker
    [ new => [ -hash => -init => 'a' ] ];

=item new_with_args

Although v1 calls will continue to work, this is not supported in v2, for it
is a trivial application of C<new_with_init>.

=item new_with_init

  use Class::MethodMaker
    [ new => [ -init => 'a' ] ];

=item object

  use Class::MethodMaker
    [ scalar => [{ -type    => 'MyClass',
                   -forward => [qw/ method1 method2 /] }, 'a' ]
    ];

=item object_tie_hash

  use Class::MethodMaker
    [ hash => [{ -type      => 'MyClass',
                 -forward   => [qw/ method1 method2 /],
                 -tie_class => 'Tie::MyTie',
                 -tie_args  => [qw/ foo bar baz /],
               }, 'a' ]
    ];

=item object_tie_list

  use Class::MethodMaker
    [ array => [{ -type      => 'MyClass',
                  -forward   => [qw/ method1 method2 /],
                  -tie_class => 'Tie::MyTie',
                  -tie_args  => [qw/ foo bar baz /],
                }, 'a' ]
    ];

=item set_once

  use Class::MethodMaker
    [ scalar => [{ -store_cb => sub {
                                  die "Already stored $_[3]"
                                    if @_ > 3;
                                }
                 },
                 'a' ]
    ];


=item set_once_static

  use Class::MethodMaker
    [ scalar => [{ -store_cb => sub {
                                  die "Already stored $_[3]"
                                    if @_ > 3;
                                },
                   -static   => 1,
                 },
                 'a' ]
    ];


=item singleton

  use Class::MethodMaker
    [ new => [ -singleton => -hash => -init => 'a' ] ];

=item static_get_set

  use Class::MethodMaker
    [ scalar => [ -static => 'a' ], ];

=item static_hash

  use Class::MethodMaker
    [ hash => [ -static => 'a' ], ];

=item static_list

  use Class::MethodMaker
    [ list => [ -static => 'a' ], ];

=item tie_hash

  use Class::MethodMaker
    [ hash => [ { -tie_class => 'MyTie',
                  -tie_args  => [qw/ foo bar baz /],
                } => 'a' ], ];

=item tie_list

  use Class::MethodMaker
    [ array => [ { -tie_class => 'MyTie',
                   -tie_args  => [qw/ foo bar baz /],
                 } => 'a' ], ];

=item tie_scalar

  use Class::MethodMaker
    [ scalar => [ { -tie_class => 'MyTie',
                    -tie_args  => [qw/ foo bar baz /],
                  } => 'a' ], ];

=back

=head2 Caveats & Expected Breakages

The following version 1 component (slot) types are not currently supported in
version 2:

=over 4

=item grouped_fields

=item hash_of_lists

=item listed_attrib

=item struct

=back

=cut

# ----------------------------------------------------------------------------

# Pragmas -----------------------------

require 5.006;
use strict;
use warnings;

# Inheritance -------------------------

use base qw( Exporter );
our @EXPORT_OK = qw( V1COMPAT );

# Utility -----------------------------

use Carp qw( );
use Class::MethodMaker::Constants qw( );

# ----------------------------------------------------------------------------

# CLASS METHODS --------------------------------------------------------------

# -------------------------------------
# CLASS CONSTANTS
# -------------------------------------

use constant INTEGER => Class::MethodMaker::Constants::INTEGER;

use constant SCALAR_RENAME => +{ '*_clear' => 'clear_*',
                                 '*_get'   => 'get_*',
                                 '*_set'   => 'set_*',   };

use constant SCALAR_ONLY_X_RENAME => +{ '*_clear' => undef,
                                        '*_reset' => undef,
                                        '*_isset' => undef, };
use constant GET_SET_PATTERN_MAP =>
  +{ -java          => [ undef, undef,     'get*', 'set*'  ],
     -eiffel        => [ undef, undef,     '*',    'set_*' ],
     -compatibility => [ '*',   'clear_*', undef,  undef   ],
     -noclear       => [ '*',   undef,     undef,  undef   ],
   };

use constant LIST_RENAME => +{ '*_ref'     => '*_ref',
                               '*_reset'   => ['*_clear',   'clear_*'  ],
                               '*_isset'   => undef,
                               '*_get'     => undef,
                               '*_set'     => undef,

                               '*_count'   => ['*_count',   'count_*'  ],
                               '*_index'   => ['*_index',   'index_*'  ],
                               '*_pop'     => ['*_pop',     'pop_*'    ],
                               '*_push'    => ['*_push',    'push_*'   ],
                               '*_set'     => ['*_set',     'set_*'    ],
                               '*_shift'   => ['*_shift',   'shift_*'  ],
                               '*_splice'  => ['*_splice',  'splice_*' ],
                               '*_unshift' => ['*_unshift', 'unshift_*'], };

use constant HASH_RENAME => +{ '*_v1compat' => '*',
                               '*_tally'    => '*_tally',
                               '*'          => undef,     };

use constant HASH_OPT_HANDLER => sub { $_[3]->{substr($_[1], 1)} = 1; };

# -------------------------------------

sub rephrase_prefix_option {
  my @opts = @_;
  return sub {
    return [@opts, ref $_[0] eq 'ARRAY'  ? @{$_[0]} : $_[0] ];
  }
}

sub rephrase_tie {
  # This is deliberately low on error-handling.
  # We're not supporting V1 programming; if it works
  # with V1, all is well; if it doesn't, use the V2
  # approach.  We don't want people coding up new stuff
  # in V1 mode.
  #
  # I.e., anything that currently works with V1 is supported, but
  # only to avoid breakage of existing classes.  All future development
  # should be done in V2 mode.
  my ($names) = @_;
  my @names; # Result
  for (my $i = 0; $i < @$names; $i+=2) {

    my ($comps, $args) = @{$names}[$i,$i+1];
    my @comps = ref $comps eq 'ARRAY' ? @$comps : $comps;
    my @args  = ref $args  eq 'ARRAY' ? @$args  : $args;
    my ($tie_class, @tie_args) = @args;
    push @names, { -tie_class => $tie_class,
                   -tie_args  => \@tie_args,
                 };
    push @names, @comps;
  }
  return \@names;
}

sub rephrase_object_tie {
  # This is deliberately low on error-handling.
  # We're not supporting V1 programming; if it works
  # with V1, all is well; if it doesn't, use the V2
  # approach.  We don't want people coding up new stuff
  # in V1 mode.
  #
  # I.e., anything that currently works with V1 is supported, but
  # only to avoid breakage of existing classes.  All future development
  # should be done in V2 mode.
  my ($comps) = @_;

  my @args;
  for my $comp (@$comps) {
    my ($tie_class, @tie_args) = @{$comp->{tie_hash}};
    my ($class, @c_args)       = @{$comp->{class}};
    my $dctor = @c_args ? 'new' : sub { $class->new(@c_args) };
    my %opts = (-type         => $class,
                -tie_class    => $tie_class,
                -default_ctor => $dctor,
               );
    $opts{-tie_args} = \@tie_args
      if @tie_args;
    push @args, \%opts, ref($comp->{slot}) ? @{$comp->{slot}} : $comp->{slot};
  }
  return \@args;
}

# -------------------------------------

sub code_store_cb {
  # A call to read with args (that aren't code references) appears to V2 to
  # be a store call
  # :-(
  # therefore we sneak the args in to an array for read to use when called
  # ;-/
  if ( ref ( $_[1] ) eq 'CODE' ) {
    # A store is immediately followed by a read.  Use undef in position 1
    # (second element) as a marker of a recent store that should therefore
    # be returned without invocation.
      return [ $_[1], undef ];
  } else {
    return [ $_[3]->[0], [ @_[4..$#_] ] ];
  }
}

# -------------------------------------

sub passthrough_option {
  # Simple pass through
  my ($type, $opt, $rename, $local_opts) = @_;
  if ( ref $opt ) {
    while ( my ($optname, $optval) = each %$opt ) {
      $local_opts->{substr($optname, 1)} = $optval;
    }
  } else {
    $local_opts->{substr($opt, 1)} = 1;
  }
}

sub get_set_option {
  my ($type, $opt, $rename, $local_opts, $class) = @_;
  my @names;
  if ( ref $opt ) {
    if ( UNIVERSAL::isa($opt, 'ARRAY') ) {
      @names = @$opt;
    } elsif ( UNIVERSAL::isa($opt, 'HASH') ) {
      $local_opts->{substr($_, 1)} = $opt->{$_}
        for keys %$opt;
    } else {
      die("Option type " . ref($opt) . " not handled by get_set\n");
    }
  } else {
    if ( exists GET_SET_PATTERN_MAP()->{$opt} ) {
      @names = @{GET_SET_PATTERN_MAP()->{$opt}};
    } else {
      if ( $opt eq '-static' ) {
        $local_opts->{static} = 1;
      } elsif ( $opt =~ /^-(?:set_once(?:_or_(\w+))?)/ ) {
        my ($action_name) = $1 || 'die';

        my %is_set;
        if ($action_name eq 'ignore') {
          $local_opts->{store_cb} = sub {
            # Have to do this here, not prior to the sub, because the
            # options hash is not available until the methods have been
            # installed
            my $options =
              Class::MethodMaker::Engine->_class_comp_options($class,
                                                              $_[2]);
            if ( exists $options->{static} ) {
              $is_set{$_[2]}++ ? $_[3] : $_[1];
            } else {
              if ( exists $is_set{$_[2]} and
                   grep $_ == $_[0], @{$is_set{$_[2]}} ) {
                $_[3];
              } else {
                push @{$is_set{$_[2]}}, $_[0];
                $_[1];
              }
            }
          };
        } elsif ($action_name =~ /carp|cluck|croak|confess/) {
          $local_opts->{store_cb} = sub {
            # Have to do this here, not prior to the sub, because the
            # options hash is not available until the methods have been
            # installed
            my $options =
              Class::MethodMaker::Engine->_class_comp_options($class,
                                                              $_[2]);
            my $action = join '::', 'Carp', $action_name;
            no strict 'refs';
            if ( exists $options->{static} ) {
              $is_set{$_[2]}++ ? &$action("Attempt to set slot ",
                                          ref($_[0]), '::', $_[2],
                                          " more than once")
                               : $_[1];
            } else {
              if ( exists $is_set{$_[2]} and
                   grep $_ == $_[0], @{$is_set{$_[2]}} ) {
                &$action("Attempt to set slot ",
                         ref($_[0]), '::', $_[2],
                         " more than once")
              } else {
                push @{$is_set{$_[2]}}, $_[0];
                $_[1];
              }
            }
          };
        } elsif ($action_name =~ /die|warn/){
          my $action = join '::', 'CORE', $action_name;
          $action = eval("sub { $action(\@_) }");
          $local_opts->{store_cb} = sub {
            # Have to do this here, not prior to the sub, because the
            # options hash is not available until the methods have been
            # installed
            my $options =
              Class::MethodMaker::Engine->_class_comp_options($class,
                                                              $_[2]);
            if ( exists $options->{static} ) {
              $is_set{$_[2]}++ ? $action->("Attempt to set slot ",
                                           ref($_[0]), '::', $_[2],
                                           " more than once")
                               : $_[1];
            } else {
              if ( exists $is_set{$_[2]} and
                   grep $_ == $_[0], @{$is_set{$_[2]}} ) {
                $action->("Attempt to set slot ",
                          ref($_[0]), '::', $_[2],
                          " more than once")
              } else {
                push @{$is_set{$_[2]}}, $_[0];
                $_[1];
              }
            }
          };
        } else {
          $local_opts->{store_cb} = sub {
            # Have to do this here, not prior to the sub, because the
            # options hash is not available until the methods have been
            # installed
            my $options =
              Class::MethodMaker::Engine->_class_comp_options($class,
                                                              $_[2]);
            my $action = join '::', ref($_[0]), $action_name;
            no strict 'refs';
            if ( exists $options->{static} ) {
              $is_set{$_[2]}++ ? &{$action}(@_[4..$#_])
                               : $_[1];
            } else {
              if ( exists $is_set{$_[2]} and
                   grep $_ == $_[0], @{$is_set{$_[2]}} ) {
                &{$action}(@_[4..$#_]);
              } else {
                push @{$is_set{$_[2]}}, $_[0];
                $_[1];
              }
            }
          };
        }
      } else {
        die "Option $opt not recognized for get_set\n";
      }
    }
  }

  $local_opts->{static} = 1
    if $type eq 'static_get_set';

  for (0..3) {
    $rename->{qw( * *_clear *_get *_set )[$_]} = $names[$_]
      if $_ < @names;
  }
};

sub key_option {
  my ($v1type, $name, $rename, $local_opts, $target_class) = @_;
  my %list;

  if ( $name eq '-dummy' ) {
    $local_opts->{_value_list} = \%list;
    $local_opts->{key_create} = 1
      if substr($v1type, -6) eq 'create';
    $local_opts->{store_cb} = sub {
      if ( defined $_[3] ) {
        # the object must be in the hash under its old
        # value so that entry needs to be deleted
        delete $list{$_[3]};
      }
      if ( defined $_[1]        and
           exists $list{$_[1]}  and
           $list{$_[1]} ne $_[0] ) {
        # There's already an object stored under that
        # value so we need to unset it's value
        my $x = $_[2];
        $list{$_[1]}->$x(undef);
      }

      $list{$_[1]} = $_[0]
        if defined $_[1];
      $_[1];
    }
  } else {
    die "Option '$_' to get_concat unrecognized\n";
  }
}

sub object_tie_option  {
  my ($type, $opt, $rename, $local_opts) = @_;
  if ( ref $opt ) {
    while ( my ($optname, $optval) = each %$opt ) {
      $local_opts->{substr($optname, 1)} = $optval
        unless $optname eq '-ctor_args';
    }
  } else {
    $local_opts->{substr($opt, 1)} = 1;
  }

  my $el_type = $opt->{-type};
  my $ctor = $opt->{-default_ctor};
  my $ctor_args = $opt->{-ctor_args};
  $local_opts->{store_cb} = sub {
    my (undef, $value) = @_;

    [ map {
      if ( UNIVERSAL::isa($_, $el_type) ) {
        $_;
      } elsif ( ref($_) eq 'ARRAY' ) {
        # Nasty hack for nasty inconsistency in V1 implementations
        my @args = index($type, 'hash') >= 0 ? (@$ctor_args, @$_) : @$_;
        $el_type->$ctor(@args);
      } else {
        $el_type->$ctor(@$ctor_args);
      }
    } @$value ];
  };
}

# -------------------------------------

# Hackery for get_concat
my $gc_join = '';

# Recognized keys are:
#   v2name
#     Name of v2 component type that implements this v1 call under the hood
#   rename
#     Method renames to apply (see create_methods) to make this look like the
#     v1 call
#   option
#     Subr called to parse options.
#     Receieves args
#       type       ) The type of the component, as called by the user
#                    (e.g., static_get_set)
#       opt        ) The name of the option (including any leading '-').
#       rename     ) The rename hashref, as set up by rename above
#       local_opts ) An option hash.  This is initially empty, it is the job
#                    of the subr to add/subtract items to this as necessary.
#                    Items may/shall acummulate as options are invoked on a
#                    single typecall.
#   rephrase
#     Subr to rephrase arguments to a type call.  If defined, this subr is
#     handed the arguments to the component type, in raw incoming form, and
#     its return value is used in place.  This is to allow arbitrary argument
#     juggling.
use constant V1COMPAT =>
  {
   # New Methods --------------------

   new => +{},

   new_hash_with_init => +{ v2name   => 'new',
                            option => HASH_OPT_HANDLER,
                            rephrase =>
                              rephrase_prefix_option(qw( -hash -init )),
                          },

   new_with_init => +{ v2name   => 'new',
                       option => HASH_OPT_HANDLER,
                       rephrase => rephrase_prefix_option(qw( -init ))
                     },

   new_hash_init => +{ v2name   => 'new',
                       option => HASH_OPT_HANDLER,
                       rephrase => rephrase_prefix_option(qw( -hash )),
                     },

   singleton     => +{ v2name   => 'new',
                       option => HASH_OPT_HANDLER,
                       rephrase =>
                         rephrase_prefix_option(qw(-hash -singleton -init)),
                     },

   # This is provided only for v1 compatibility; no attempt is made to
   # support this in V2, for it is a trivial application of new_with_init.
   new_with_args => +{ v2name   => 'new',
                       option => HASH_OPT_HANDLER,
                       rephrase => rephrase_prefix_option(qw( -direct-init ))
                     },


   # Copy Methods -------------------

   copy => +{},
   deep_copy => +{ v2name => 'copy',
                   option => sub {
                     $_[3]->{deep} = 1;
                   },
                   rephrase => rephrase_prefix_option('-dummy'),
                 },

   # Scalar Methods -----------------

   get_set =>        { v2name => 'scalar',
                       rename => SCALAR_RENAME,
                       option => \&get_set_option,
                     },
   static_get_set => {
                      v2name   => 'scalar',
                      rename   => SCALAR_RENAME,
                      option   => \&get_set_option,
                      rephrase => rephrase_prefix_option('-static'),
                     },
   tie_scalar     => { v2name    => 'scalar',
                       rename   => SCALAR_RENAME,
                       rephrase => \&rephrase_tie,
                       option   => \&get_set_option,
                     },
   counter =>        { v2name => 'scalar',
                       rename => SCALAR_RENAME,
                       option => \&passthrough_option,
                       rephrase =>
                         rephrase_prefix_option(+{-type => INTEGER}),
                     },
   get_concat =>     { v2name => 'scalar',
                       rename => SCALAR_RENAME,
                       option => sub {
                         my ($type, $opt, $rename, $local_opts) = @_;

                         if ( ref $opt ) {
                           for ( keys %$opt ) {
                             if ( $_ eq '-join' ) {
                               $gc_join = $opt->{-join};
                             } else {
                               die "Option '$_' to get_concat unrecognized\n";
                             }
                           }
                         } elsif ( $opt eq '-dummy' ) {
                           my $join = $gc_join;
                           $local_opts->{store_cb} =
                             sub {
                               defined $_[1] ?
                                 (defined $_[3] ? "$_[3]$join$_[1]" : $_[1] ) :
                                   undef;
                             };
                           $gc_join = '';
                         } else {
                           $local_opts->{substr($opt, 1)} = 1;
                         }
                       },
                       rephrase => sub {
                         my @opts = @_;
                         if ( UNIVERSAL::isa($_[0], 'HASH') ) {
                           return [ +{ -join => $_[0]->{join}},
                                    '-dummy',
                                    $_[0]->{name}
                                  ];
                         } else {
                           return ['-dummy',
                                   ref $_[0] eq 'ARRAY' ? @{$_[0]} : $_[0] ];
                         }
                       },
                     },
   key_attrib =>     { v2name => 'scalar',
                       rename => +{ %{SCALAR_RENAME()},
                                    '*_find' => 'find_*', },
                       option => \&key_option,
                       rephrase => rephrase_prefix_option(qw( -dummy )),
                     },

   key_with_create =>{ v2name => 'scalar',
                       rename => +{ %{SCALAR_RENAME()},
                                     '*_find' => 'find_*', },
                       option => \&key_option,
                       rephrase => rephrase_prefix_option(qw( -dummy )),
                     },

   # Code-Based Types
   code           => { v2name    => 'scalar',
                       rename   => SCALAR_ONLY_X_RENAME,
                       rephrase => rephrase_prefix_option('-dummy'),
                       option   => sub {
                         my ($type, $opt, $rename, $local_opts) = @_;
                         # Let's face it, the V1 i/f, with it's
                         # store-if-it's-a-coderef-else-retrieve semantics
                         # is rather broken.  Which is why we engage in such
                         # hackery...
                         $local_opts->{read_cb} =
                           sub {
                             if  ( ref($_[1]) eq 'ARRAY' ) {
                               if ( @{$_[1]} == 1 ) { # No args
                                 return $_[1]->[0]->();
                               } elsif ( defined $_[1]->[1] ) {
                                 # Read with args that was handed to store
                                 return $_[1]->[0]->(@{$_[1]->[1]});
                               } else {
                                 # We're reading after a recent store
                                 pop @{$_[1]};
                                 return $_[1]->[0];
                               }
                             }
                           };
                         $local_opts->{store_cb} = \&code_store_cb;
                       },
                     },

   method         => { v2name    => 'scalar',
                       rename   => SCALAR_ONLY_X_RENAME,
                       rephrase => rephrase_prefix_option('-dummy'),
                       option   => sub {
                         my ($type, $opt, $rename, $local_opts) = @_;
                         # Let's face it, the V1 i/f, with it's
                         # store-if-it's-a-coderef-else-retrieve semanntics
                         # is rather broken.  Which is why we engage in such
                         # hackery...
                         $local_opts->{read_cb} =
                           sub {
                             if  ( ref($_[1]) eq 'ARRAY' ) {
                               if ( @{$_[1]} == 1 ) { # No args
                                 return $_[1]->[0]->($_[0]);
                               } elsif ( defined $_[1]->[1] ) {
                                 # Read with args that was handed to store
                                 return $_[1]->[0]->($_[0], @{$_[1]->[1]});
                               } else {
                                 # We're reading after a recent store
                                 pop @{$_[1]};
                                 return $_[1]->[0];
                               }
                             }
                           };
                         $local_opts->{store_cb} = \&code_store_cb;
                       },
                     },

   # List Methods -------------------

   object => {
              v2name => 'scalar',
              rephrase => sub {
                my ($names) = @_;

                die("v1 meta-method object requires an arrayref as it's ",
                    "argument\n")
                  unless UNIVERSAL::isa($names, 'ARRAY');

                my @Results;

                while ( my($type, $args) = splice @$names, 0, 2 ) {
                  die("type specifier to v1 object must be a non-ref ",
                      "value\n")
                    if ref $type;

                  for (UNIVERSAL::isa($args, 'ARRAY') ? @$args : $args) {
                    my (@names, @fwds);
                    if ( ! ref $_ ) {
                      @names = $_;
                    } elsif ( UNIVERSAL::isa($_, 'HASH') ) {
                      @names = $_->{slot};
                      @fwds  = $_->{comp_mthds};
                      @fwds  = @{$fwds[0]}
                        if UNIVERSAL::isa($fwds[0], 'ARRAY');
                    } else {
                      die("Argument $_ to 'object' v1 meta-method not ",
                          "comprehended\n");
                    }

                    push (@Results,
                          { -type         => $type,
                            -forward      => \@fwds,
                            -default_ctor => 'new',
                            -v1_object    => 1,
                          },
                          @names);
                  }
                }
                \@Results;
              },
              option => \&passthrough_option,
             },

   list => { v2name => 'array',
             rename => LIST_RENAME,
           },
   static_list => { v2name => 'array',
                    rename => LIST_RENAME,
                    rephrase => rephrase_prefix_option('-static'),
                    option => sub {
                      my ($type, $opt, $rename, $local_opts) = @_;
                      $local_opts->{static} = 1;
                    },
                  },

   object_list => { v2name => 'array',
                    rename => LIST_RENAME,
                    rephrase => sub {
                      # This is deliberately low on error-handling.
                      # We're not supporting V1 programming; if it works
                      # with V1, all is well; if it doesn't, use the V2
                      # approach.  We don't want people coding up new stuff
                      # in V1 mode.
                      my ($names) = @_;
                      my @names; # Result
                      for (my $i = 0; $i < @$names; $i+=2) {
                        my ($class, $args) = @{$names}[$i,$i+1];
                        my @args = ref $args eq 'ARRAY' ? @$args : $args;

                        push @names, +{ -type => $class,
                                        -default_ctor => 'new' };

                        for my $arg (@args) {
                            if ( ref $arg eq 'HASH' ) {
                            my ($slot, $comp_mthds) =
                              @{$arg}{qw( slot comp_mthds )};
                            my @comp_mthds =
                              ref $comp_mthds ? @$comp_mthds : $comp_mthds;
                            push @names, +{ -forward => \@comp_mthds }
                              if @comp_mthds;
                            push @names, $slot;
                          } else {
                            push @names, $arg;
                          }
                        }
                      }
                      return \@names;
                    },
                    option => \&passthrough_option,
                  },
   tie_list => { v2name => 'array',
                 rename => LIST_RENAME,
                 rephrase => \&rephrase_tie,
                 option => \&passthrough_option,
               },
   object_tie_list => { v2name => 'array',
                        rename => LIST_RENAME,
                        rephrase => sub {
                          # This is deliberately low on error-handling.
                          # We're not supporting V1 programming; if it works
                          # with V1, all is well; if it doesn't, use the V2
                          # approach.  We don't want people coding up new
                          # stuff in V1 mode.
                          my ($names) = @_;
                          my @names; # Result
                          for my $hashr (@$names) {
                            my ($slots, $class, $tie_args) =
                              @{$hashr}{qw( slot class tie_array )};
                            my @slots = ref $slots eq 'ARRAY' ?
                                                      @$slots : $slots;
                            my @class_args;
                            ($class, @class_args) = @$class
                              if ref $class eq 'ARRAY';
                            my $ctor;
                            if ( @class_args ) {
                              $ctor = sub {
                                return $class->new(@class_args);
                              };
                            } else {
                              $ctor = 'new';
                            }
                            my ($tie_class, @tie_args) =
                              @$tie_args;
                            push @names, +{ -type => $class,
                                            -default_ctor => 'new',
                                            -ctor_args => \@class_args,
                                            -tie_class => $tie_class,
                                            -tie_args  => \@tie_args,};

                            push @names, @slots;
                          }
                          return \@names;
                        },
                        option => \&object_tie_option,
                      },
   object_tie_hash => { v2name => 'hash',
                        rename => HASH_RENAME,
                        rephrase => sub {
                          # This is deliberately low on error-handling.
                          # We're not supporting V1 programming; if it works
                          # with V1, all is well; if it doesn't, use the V2
                          # approach.  We don't want people coding up new
                          # stuff in V1 mode.
                          my ($names) = @_;
                          my @names; # Result
                          for my $hashr (@$names) {
                            my ($slots, $class, $tie_args) =
                              @{$hashr}{qw( slot class tie_hash )};
                            my @slots = ref $slots eq 'ARRAY' ?
                                                      @$slots : $slots;
                            my @class_args;
                            ($class, @class_args) = @$class
                              if ref $class eq 'ARRAY';
                            my $ctor;
                            if ( @class_args ) {
                              $ctor = sub {
                                return $class->new(@class_args);
                              };
                            } else {
                              $ctor = 'new';
                            }
                            my ($tie_class, @tie_args) =
                              @$tie_args;
                            push @names, +{ -type => $class,
                                            -default_ctor => 'new',
                                            -ctor_args => \@class_args,
                                            -tie_class => $tie_class,
                                            -tie_args  => \@tie_args,};

                            push @names, @slots;
                          }
                          return \@names;
                        },
                        option => \&object_tie_option,
                      },

   # Hash Methods -------------------

   hash           => +{
                       rename => HASH_RENAME,
                      },
   static_hash     => {
                       v2name   => 'hash',
                       rename   => HASH_RENAME,
                       option   => \&passthrough_option,
                       rephrase => rephrase_prefix_option('-static'),
                      },
   tie_hash        => { v2name => 'hash',
                        rename => HASH_RENAME,
                        rephrase => \&rephrase_tie,
                        option => \&passthrough_option,
                      },

   # Misc Methods -------------------

   abstract => +{},
   boolean         => { v2name => '_boolean',
                        rename => +{ '*_set' => 'set_*',
                                     '*_clear' => 'clear_*', }, },
 };

# ----------------------------------------------------------------------------

=head1 EXAMPLES

Z<>

=head1 BUGS

Z<>

=head1 REPORTING BUGS

Email the development mailing list C<class-mmaker-devel@lists.sourceforge.net>.

=head1 AUTHOR

Martyn J. Pearce

=head1 COPYRIGHT

Copyright (c) 2003, 2004 Martyn J. Pearce.  This program is free software; you
can redistribute it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

Z<>

=cut

1; # keep require happy.

__END__
