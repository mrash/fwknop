# (X)Emacs mode: -*- cperl -*-

package Class::MethodMaker::Engine;

=head1 NAME

Class::MethodMaker::Engine - The parameter passing, method installation &
non-data-structure methods of Class::MethodMaker.

=head1 SYNOPSIS

This class is for internal implementation only.  It is not a public API.

The non-data-structure methods do form part of the public API, but not called
directly: rather, called through the C<use>/C<import> interface, as for
data-structure methods.

=cut

# Pragmas -----------------------------

use 5.006;
use strict;
use warnings;

use warnings::register;

# Inheritance -------------------------

our @ISA = qw( AutoLoader );

# Utility -----------------------------

use AutoLoader                   qw( AUTOLOAD );
use Carp                         qw( carp croak cluck );
use Class::MethodMaker::OptExt   qw( OPTEXT );
use Class::MethodMaker::V1Compat qw( V1COMPAT );

# ----------------------------------------------------------------------------

# CLASS METHODS --------------------------------------------------------------

# -------------------------------------
# CLASS CONSTANTS
# -------------------------------------

# Weird "useless use of a constant in void context" without the ?:
use constant DEBUG => $ENV{_CMM_DEBUG} ? 1 : 0;
BEGIN {
  if ( DEBUG ) {
    require B::Deparse;
    require Data::Dumper;
    Data::Dumper->import('Dumper');
  }
}

# -------------------------------------

our $PACKAGE = 'Class-MethodMaker';
our $VERSION = '2.11';

# -------------------------------------
# CLASS CONSTRUCTION
# -------------------------------------

# -------------------------------------
# CLASS COMPONENTS
# -------------------------------------

# A starter for introspective information

# For each class, a list of the components installed for that class (as a
# hashref from name to hashref.  Keys of latter hashref:
# 'type'   name of component type, e.g., scalar, array, hash
# 'assign' name of method to perform assignment.  This is used by new with
#          hash_init.  This level of indirection is to cater for the
#          possibility of an assignment function named other than '*'

my %class_comps;
sub _class_comp_assign {
  exists $class_comps{$_[1]}->{$_[2]}      ?
    $class_comps{$_[1]}->{$_[2]}->{assign} : undef;
}

sub _class_comp_options {
  exists $class_comps{$_[1]}->{$_[2]}      ?
    $class_comps{$_[1]}->{$_[2]}->{options} : undef;
}

# -------------------------------------
# CLASS HIGHER-LEVEL FUNCTIONS
# -------------------------------------

# -------------------------------------
# CLASS HIGHER-LEVEL PROCEDURES
# -------------------------------------

=head1 The Class::MethodMaker Method Installation Engine

Z<>

=cut

# -------------------------------------

=head2 import

This performs argument parsing ready for calling create_methods.  In
particular, this is the point at which v1 & v2 calls are distinguished.

This is implicitly called as part of a C<use> statement:

  use Class::MethodMaker
    [ scalar => [qw/ foo bar baz /],
      new    => [qw/ new /]        ,
    ];

is equivalent to

  Class::MethodMaker->import([scalar => [qw/ foo bar baz /],
                              new    => [qw/ new /]        ,
                             ]);

See L<perldoc -f use|use> for details of this equivalence.

The methods created are installed into the class calling the import - or more
accurately, the first class up the calling stack that is not
C<Class::MethodMaker> or a subclass thereof.

=over 4

=item SYNOPSIS

  Class::MethodMaker->import([scalar => [+{ -type   => 'File::Stat',
                                            -forward => [qw/ mode size /],
                                            '*_foo' => '*_fig',
                                            '*_gop' => undef,
                                            '*_bar' => '*_bar',
                                            '*_hal' => '*_sal',
                                           },
                                         qw/ -static bob /,
                                        ]
                             ]);

=back

=cut

sub import {
  my $class = shift;
  my $target = $class->_find_target_class;

  my (@args);
  my $mode = 2;

  return unless @_;

  if ( @_ == 1 ) {
    croak "import requires an arrayref"
      unless UNIVERSAL::isa($_[0], 'ARRAY');
    @args = @{$_[0]};
  } else {
    croak("import requires an even number of arguments in v1 compatibility ".
          "mode")
      unless @_ % 2 == 0;

    @args = @_;
    # -1 on $#args ensures that no range is generated when $#args is 0.
    # check above ensures that scalar(@args) is even, so $#args is odd,
    # so $#args-1 is even and ($#args-1)/2 == int ($#args/2).  .. provides an
    # integer context to its operands.
    $mode = 1
      for grep exists V1COMPAT->{$_}, map $args[$_*2], 0..($#args-1)/2;
    if ( $mode == 1 ) {
      croak("meta-method type $_ not recognized as a V1 compatibility type\n" .
            "(cannot mix v1 & v2 options)\n")
        for grep ! exists V1COMPAT->{$_}, map $args[$_*2], 0..($#args-1)/2;
    } else {
      croak('meta-method' . (($#args/2>1) ? 's' : '') . ' '                  .
            join(', ', map qq'"$args[$_*2]"', 0..($#args-1)/2)               .
            " found in v1 compatibility mode, but not recognized as v1.\n"   .
            "please update to v2, presenting your arguments to use/import\n" .
            "as a single arrayref (wrap them with [...])\n");
    }
  }

  if ( $mode == 1 ) {
    $class->parse_v1_options($target, \@args);
  } else {
    $class->parse_options($target, \@args);
  }
}

# -------------------------------------

=head2 parse_options

Parse the arguments given to import and call L<create_methods|create_methods>
appropriately.  See main text for options syntax.

=over 4

=item SYNOPSIS

  Class::MethodMaker->parse_options('TargetClass',
                                    [scalar =>
                                      [{ -type => 'File::stat',
                                         -forward => [qw/ mode
                                                          size /],
                                         '*_foo' => '*_fig',
                                         '*_gop' => undef,
                                         '*_bar' => '*_bar',
                                         '*_hal' => '*_sal',
                                       },
                                       qw( -static bob ),
                                      ]])},

  Class::MethodMaker->parse_options('TargetClass2',
                                    [scalar =>
                                      ['baz',
                                       { -type => 'File::stat',
                                         -forward => [qw/ mode
                                                          size /],
                                         '*_foo' => '*_fog',
                                         '*_bar' => '*_bar',
                                         '*_hal' => '*_sal',
                                       },
                                       qw( -static bob ),
                                      ]],
                                    +{ -type => 'Math::BigInt', },
                                    +{'*_foo' => '*_fig',
                                      '*_gop' => undef,},
                                   )},



=item ARGUMENTS

=over 4

=item target_class

The class into which to install components

=item args

The arguments to parse, as a single arrayref.

=item options

A hashref of options to apply to all components created by this call (subject
to overriding by explicit option calls).

=item renames

A hashref of renames to apply to all components created by this call (subject
to overriding by explicit rename calls).

=back

=back

=cut

sub parse_options {
  my $class = shift;
  my ($target_class, $args, $options, $renames) = @_;

  print STDERR ("Parsing Options: ",
                Data::Dumper->Dump([$args, $options, $renames],
                                   [qw( args options renames )]))
    if DEBUG;

  my (%options, %renames);

  # It is important that components are created in the specified order, so
  # that e.g., forwarding works as expected (lest the forward method applies
  # to the wrong component).

  for (my $i = 0; $i < @$args; $i++) {
    if ( ! ref $args->[$i] ) {
      my $type = $args->[$i];

      if ( substr($type, 0, 1) eq '-' ) {
        my $option = substr($type, 1);
        if ( $option eq 'target_class' ) {
          croak "No argument found for -target_class\n"
            if $i == $#$args;
          $target_class = $args->[++$i];
          croak "-target_class takes a simple scalar argument\n"
            if ref $target_class;
        } else {
          croak "Unrecognized option: $type\n";
        }
      } else {
        # Reset options, renames to input global settings
        %options = defined $options ? %$options : ();
        %renames = defined $renames ? %$renames : ();
        my $created = 0;
        croak("No arguments found for $type while creating methods for ",
              $target_class, "\n")
          if $i == $#$args;
        my $opts = $args->[++$i];
        if ( UNIVERSAL::isa($opts, 'SCALAR') ) {
          $class->create_methods ($target_class, $type, $opts,
                                  \%options, \%renames);
          $created = 1;
        } elsif ( UNIVERSAL::isa($opts, 'ARRAY') ) {
          for (@$opts) {
            if ( ! ref $_ ) {
              if ( $_ =~ /^[A-Za-z_][0-9A-Za-z_]*$/ ) {
                $class->create_methods ($target_class, $type, $_,
                                        \%options, \%renames);
                $created = 1;
              } elsif ( $_ =~ /^([-!])([0-9A-Za-z_]+)$/ ) {
                $options{$2} = ($1 eq '!' ? 0 : 1);
              } else {
                croak "Argument $_ for type $type not understood\n";
              }
            } elsif ( UNIVERSAL::isa($_, 'HASH') ) {
              while ( my ($k, $v) = each %$_ ) {
                if ( index($k, '*') > $[-1 ) {
                  $renames{$k} = $v;
                } else {
                  $k =~ s/^-//;
                  $options{$k} = $v;
                }
              }
            } elsif ( UNIVERSAL::isa($_, 'ARRAY') ) {
              $class->parse_options($target_class, [$type, $_],
                                    \%options, \%renames);
            } else {
              croak("Argument type " . ref($_) .
                    " to type $type not handled\n");
            }
          }
        } else {
          $class->create_methods ($target_class, $type, $opts,
                                  $options, $renames);
          $created = 1;
        }

        warnif("No attributes found for type $type\n")
          unless $created;
      }
    } else {
      croak "Argument not handled: ", $args->[$i], "\n";
    }
  }

  return;
}

# -------------------------------------

# V1 compatibility is purposely not documented.

sub parse_v1_options {
  my $class = shift;
  my ($target_class, $args) = @_;

  print STDERR "V1 Parser (1) : ", Data::Dumper->Dump([$args],
                                                          [qw( args )])
    if DEBUG;

  while (my ($v1type, $names) = splice @$args, 0, 2 ) {
    my %options = (v1_compat => 1);

    croak("No argument found for $v1type while creating methods for ",
          $target_class, "\n")
      unless defined $names;

    my $v2type = $v1type;

    my ($rename, $opt_handler, $rephrase);
    if ( exists V1COMPAT->{$v1type} ) {
      my $v1compat = V1COMPAT->{$v1type};
      $v2type = $v1compat->{v2name}
        if exists $v1compat->{v2name};
      ($rename, $opt_handler, $rephrase) =
        @{$v1compat}{qw(rename option rephrase)};
      print STDERR "V1 Parser (2) : ",
        Data::Dumper->Dump([$v1type, $v2type,      $v1compat,
                            $rename, $opt_handler, $rephrase,],
                           [qw(v1type v2type        v1compat
                               rename opt_handler   rephrase)])
        if DEBUG;
    }

    print STDERR "V1 Parser (3) : ",
      Data::Dumper->Dump([$names],[qw(inames)])
      if DEBUG;
    if ( defined $rephrase ) {
      $names = $rephrase->($names);
      print STDERR "V1 Parser (3.5) : ",
        Data::Dumper->Dump([$names],[qw(rephrased)])
        if DEBUG;
    }

#    warnif("Class::MethodMaker V1 compatibility mode enabled for $type\n");

    my @names = UNIVERSAL::isa($names, 'ARRAY') ? @$names : $names;

    for (@names) {
      if ( ref($_) or substr($_, 0, 1) eq '-' ) {
        print STDERR "V1 Parser (4) : ",
          Data::Dumper->Dump([\%options, $_],[qw(options name)])
          if DEBUG;
        if ( defined $opt_handler ) {
          $opt_handler->($v1type, $_, $rename, \%options, $target_class);
        } else {
          croak "Options not handled for v1 type $v1type\n";
        }
        print STDERR "V1 Parser (4.5) : ",
          Data::Dumper->Dump([\%options],[qw(options)])
          if DEBUG;
      } else {
        $class->create_methods($target_class, $v2type, $_,
                               \%options, $rename);
      }
    }
  }
}

# -------------------------------------

=head2 create_methods

Add methods to a class.  Methods for multiple components may be added this
way, but create_methods handles only one set of options.
L<parse_options|parse_options> is responsible for sorting which options to
apply to which components, and calling create_methods appropriately.

=over 4

=item SYNOPSIS

  Class::MethodMaker->create_methods($target_class,
                                     scalar => bob,
                                     +{ static => 1,
                                        type   => 'File::Stat',
                                        forward => [qw/ mode size /], },
                                     +{ '*_foo' => '*_fig',
                                        '*_gop' => undef,
                                        '*_bar' => '*_bar',
                                        '*_hal' => '*_sal', }
                                    );

=item ARGUMENTS

=over 4

=item targetclass

The class to add methods to.

=item type

The basic data structure to use for the component, e.g., C<scalar>.

=item compname

Component name.  The name must be a valid identifier, i.e., a continguous
non-empty string of word (C<\w>) characters, of which the first may not be a
digit.

=item options

A hashref.  Some options (C<static>, C<type>, C<default>, C<default_ctor>) are
handled by the auto-extender.  These will be invoked if the name is present as
a key and the value is true.  Any other options are passed through to the
method in question.  The options should be named as-is; no leading hyphen
should be applied (i.e., use C<< {static => 1} >> not C<< {-static => 1} >>).

=item renames

A list of customer renames.  It is a hashref from method name to rename.  The
method name is the generic name (i.e., featuring a C<*> to replace with the
component name).  The rename is the value to rename with.  It may itself
contain a C<*> to replace with the component name.  If rename is undef, the
method is I<not> installed.  For methods that would not be installed by default, use a rename value that is the same as the method name.

So, if a type would normally install methods

  '*_foo', '*_gop', '*_tom'

and optionally installs (but not by default)

  '*_bar', '*_wiz', '*_hal'

using a renames value of

  { '*_foo' => '*_fig',
    '*_gop' => undef,
    '*_bar' => '*_bar',
    '*_hal' => '*_sal',
  }

with a component name of C<xx>, then C<*_foo> is installed as C<xx_fig>,
C<*_bar> is installed as C<xx_bar>, C<*_wiz> is not installed, C<*_hal> is
installed as C<xx_sal>, C<*_gop> is not installed, and C<*_tom> is installed
as C<xx_tom>.

The value may actually be an arrayref, in which case the function may be
called by any of the multiple names specified.

=back

=back

=cut

# This is the bit that does the actual creation.  For options-handling
# excitement, see import.
sub create_methods {
  my $class = shift;
  my ($targetclass, $type, $compname, $options, $renames) = @_;

  if ( exists $class_comps{$targetclass}->{$compname} ) {
    croak("The component '$compname' has already been installed in class " .
          "-->$targetclass<-- as a $class_comps{$targetclass}->{$compname}\n" .
          "  (this time a $type)\n");
  }

  print STDERR "Create methods (1) : ",
    Data::Dumper->Dump
        ([  $type, $compname, $options, $renames],
         [qw(type   compname   options   renames)]
        )
      if DEBUG;

  my (%options) = defined $options ? %$options : ();
  if ( exists $options{type} and substr($options{type}, 0, 1) eq '+' ) {
    $options{typex} = substr(delete $options{type}, 1);
    my $coerce = sub { no warnings 'numeric'; int($_[1]||0) };
    for my $optname (qw( store_cb read_cb )) {
      if ( exists $options{$optname} ) {
        $options{$optname} = [$options{$optname}]
          unless ref($options{$optname}) eq 'ARRAY';
        push @{$options{$optname}}, $coerce;
      } else {
        $options{$optname} = $coerce;
      }
    }
  }
  croak("Illegal attribute name -->$compname<--" .
        " (must be a legal perl identifier)\n")
    unless $compname =~ /^(?!\d)\w+$/;

  my ($opts, $creator);
  # Some options are handled by the cmmg.pl auto-extender.
  # Find the method-name extension & options this represents
  (my ($ext), $opts) =
    Class::MethodMaker::OptExt->encode($type,
                                       [grep $options{$_}, keys %options]);
  croak "Illegal combination of options: ", join(',', keys %options), "\n"
    if ( ! defined $ext );
  $creator = length $ext ? join('', substr($type, 0, 4), $ext) : $type;
  my $create_class = $class;
  if ( length $ext ) {
    require "Class/MethodMaker/${type}.pm";
    $create_class = "Class::MethodMaker::${type}";
  }
  print STDERR "Create methods (2) : ",
    Data::Dumper->Dump
        ([   $create_class, $creator, $ext, $opts],
         [qw( create_class   creator   ext   opts)]
        )
      if DEBUG;
  my ($methods, $names);

  eval {
    ($methods, $names) =
      $create_class->$creator($targetclass, $compname, \%options);
  }; if ( $@ ) {
    if ( $@ =~ m"^Can't locate auto/Class/MethodMaker/(\S*)" ) {
      my $message = "Couldn't find meta-method for type $type";
      $message   .= " with options -->" . join(', ', @$opts) . "<--"
        if @$opts;
      croak("$message ($creator [$create_class])\n");
    } else {
      die $@;
    }
  }

  print STDERR "Create methods (3) : ",
    Data::Dumper->Dump([$methods, $names], [qw(methods names)])
        if DEBUG;

  my $assign_name = exists $names->{'='} ? delete $names->{'='} : '*';

  if ( defined $names ) {
    croak "Names value for key $_ should not be defined ($names->{$_})\n"
      for grep defined $names->{$_}, keys %$names;
  }

  my %methods;
  my %realname;
 METHNAME:
  while ( my ($methname, $code) = each %$methods ) {
    # If a method's raw name is preceded by a '!', don't install it unless
    # explicitly requested (exists in customer renames)
    print STDERR "CREATE: Considering method $methname\n"
      if DEBUG;

    if ( index($methname, ':') > -1 ) {
      # Some typed method.  Only install if the appropriate type is specified.
      $methname =~ s/(\w+)://;
      my $type = $1;
      next METHNAME
        unless exists $options{typex} and $type eq $options{typex};
    }

    unless ( substr($methname, 0, 1) eq '!' and
             ! exists $renames->{substr($methname, 1)}   ) {
      $methname =~ s/^!//;
      my $realname = exists $renames->{$methname} ?
                     $renames->{$methname}        :
                     $methname;
      # If the subr is required (because it's used by other subrs of the
      # attribute) but isn't wanted by the user (renamed to undef), sneak it
      # into the symbol table prefixed by a space, so it's not normally
      # accessible.
      if ( ! defined $realname and exists $names->{$methname} ) {
        $realname = " $methname";
      }
      print STDERR ("CREATE: Using realname ",
                    (defined $realname                                   ?
                     (ref $realname                                  ?
                      "[" . join (',', map "'$_'", @$realname) . "]" :
                      "'$realname'")                                     :
                     '*undef*'
                    ),
                    "\n")
        if DEBUG;
      if ( defined $realname ) {
        for my $rn (ref $realname ? @$realname : $realname) {
          my $copy = $rn; # Copy to avoid clobbering the original array
          $copy =~ s/\*/$compname/g;
          print STDERR "CREATE: Installing $copy\n"
            if DEBUG;
          $methods{$copy} = $code;
          $names->{$methname} = $copy
            if defined $names;
          # It's okay if this gets assigned multiple times (because $realname
          # is an arrayref); each assignment gives it a valid name, we care
          # not which is used.
          $realname{$methname} = $copy;
        }
      } else {
        $realname{$methname} = undef;
      }
    }
  }

  print STDERR "Create methods (4) : ",
    Data::Dumper->Dump([\%methods, \%realname], [qw(*methods *realname)])
        if DEBUG;

  # Now, I want some installed methods to be able to call some others.
  # However, I also want to be able to rename methods on the fly to the
  # users' specification.
  #   I can't pass a set of renames into the component creator without the
  # caller knowing the set of names for the component to rename --- only the
  # component knows the names of the methods to create, and they may be
  # affected by arguments.  I don't want to duplicate that knowledge elsewhere.
  #   I can't have the methods call each other via names in the symbol table,
  # lest the method called gets renamed.
  #   If we have the sub called directly (without the symbol table), we get
  # burnt when users replace the method (expecting it to get called)
  # or override it from a subclass.
  #   If we don't call methods from one to another, but instead 'inline' the
  # relevant code, then we're liable to introduce more bugs (esp. as updates
  # are made) in addition to the same problem set as calling the methods
  # without the symbol table.  Therefore, we have the 'names' hash,
  # returned above.  This hash specifies a set of methods to be installed
  # whatever (i.e., even if they're not visible to the user), so that they
  # may be called by other methods.  The hash keys are the default name of
  # the method, the values are set (by this subroutine, 'create_methods') to
  # the actual code, whatever name it gets installed as.
  $class->install_methods($targetclass, \%methods);

  $class_comps{$targetclass}->{$compname} =
    +{ type    => $type                  ,
       assign  => $realname{$assign_name},
       options => \%options,
     };

  return;
}

# -------------------------------------

# Find the class to add the methods to.  I'm assuming that it would be the
# first class in the caller() stack that's not a subsclass of MethodMaker.  If
# you want something more sophisticated implement it --- and call
# create_methods, specifying exactly the target class.  If you can think of a
# better way of determining the target class, let me know!

sub _find_target_class {
  my $class = shift;

  my $target;
  my $i = 0;
  do {
    $target = (caller($i))[0];
    $i++;
  } while ( ( $target->isa('Class::MethodMaker::Engine') 
              or
              $target->isa('Class::MethodMaker') )       and
            # This is "supported" for v1 compatibility only.  Direct calling
            # of create_methods is the preferred way of using
            # Class::MethodMaker to build C::MM subclasses
           (! $target->can ('ima_method_maker') or
             ( warnif("Class::MethodMaker::ima_method_maker deprecated\n"),
               &{$target->can ('ima_method_maker')} )
            )
          );

  return $target;
}

# -------------------------------------

=head2 install_methods

=over 4

=item SYNOPSIS

  Class::MethodMaker->install_methods
    ($classname, { incr => sub { $i++ },
                   decr => sub { $i-- },
                 }
    );

=item ARGUMENTS

=over 4

=item target

The class into which the methods are to be installed

=item methods

The methods to install, as a hashref.  Keys are the method names; values are
the methods themselves, as code refs.

=back

=back

=cut

sub install_methods {
  my $class = shift;
  my ($target, $methods) = @_;

  while ( my ($name, $code) = each %$methods ) {
    if ( DEBUG ) {
      print STDERR "Installing method '$name' into $target\n";
      eval {
        my @opts = qw( -sC -i2);
        push @opts, '-l'
          if DEBUG > 1;
        print STDERR
          B::Deparse->new(@opts)->coderef2text($code), "\n";
      }; if ($@) {
        print STDERR "Couldn't deparse '$name': $@\n";
      }
    }
    my $reftype = ref $code;
    if ( $reftype eq 'CODE' ) {
      my $methname = join '::', $target, $name;
      no strict 'refs';
      if ( ! defined *{$methname}{CODE} ) {
        *{$methname} = $code;
        # Generate a unique stash name for the sub.  Use a preceding space
        # to avoid collisions with anything in the Perl space.
        Class::MethodMaker::set_sub_name($code, $target, $name, " ${target}::${name}");
      }
    } else {
      croak "What do you expect me to do with this?: $code\n";
    }
  }
}

# -------------------------------------
# CLASS UTILITY FUNCTIONS
# -------------------------------------

sub warnif { warnings::warnif (@_) };
# sub warnif { warnings::warn (@_) if (warnings::enabled()) };

sub check_opts {
  my ($known_opts, $options) = @_;

  $known_opts = +{ map {;$_=>1} @$known_opts }
    if ref $known_opts eq 'ARRAY';

  if ( my @bad_opt = grep ! exists $known_opts->{$_}, keys %$options ) {
    my $prefix = 'Option' . (@bad_opt > 1 ? 's' : '');
    croak("$prefix not recognized for attribute type scalar: ",
          join(', ', @bad_opt), "\n");
  }
}

# -------------------------------------
# META-METHODS
# -------------------------------------

1; # keep require happy

__END__

=head1 Non-data-structure components

Z<>

=cut

=head2 new

  use Class::MethodMaker
    [ new => 'new' ];

Creates a basic constructor.

Takes a single string or a reference to an array of strings as its
argument.  For each string creates a simple method that creates and
returns an object of the appropriate class.

The generated method may be called as a class method, as usual, or as in
instance method, in which case a new object of the same class as the instance
will be created.

=head3 Options

=over 4

=item -hash

The contructor will accept as arguments a list of pairs, from component name
to initial value.  For each pair, the named component is initialized by
calling the method of the same name with the given value.  E.g.,

  package MyClass;
  use Class::MethodMaker
    [ new    => [qw/ -hash new /],
      scalar => [qw/ b c /],
    ];

  sub d {
    my $self = shift;
    $self->{d} = $_[0]
      if @_;
    return $self->{d};
  }

  package main;
  # The statement below implicitly calls
  # $m->b(1); $m->c(2); $m->d(3)
  # on the newly constructed m.
  my $m = MyClass->new(b => 1, c => 2, d => 3);

Note that this can also call user-supplied methods that have the name of the
component.

Instead of a list of pairs, a single hashref may also be passed, which will be
expanded appropriately.  So the above is equivalent to:

  my $m = MyClass->new({ b => 1, c => 2, d => 3 });

I<Advanced Users:> Class::MethodMaker method renaming is taken into account,
so even if the C<*> method is renamed or removed, this will still work.

=item -init

This option causes the new method to call an initializor method.  The method
is called C<init> (original, eh?) by default, but the option may be given an
alternative value.  The init method is passed any arguments that were passed
to the constructor, but the method is invoked on the newly constructed
instance.

  use Class::MethodMaker
    [ new => [qw/ -init new1 /, { -init => 'bob' } => 'init2' ]];

Constructing with new1 involves an implicit call to C<init>, whilst
constructing with new2 involves an implicit call to C<bob> (I<instead> of
C<init>).

It is the responsiblity of the user to ensure that an C<init> method (or
whatever name) is defined.

=item -singleton

Creates a basic constructor which only ever returns a single instance of the
class: i.e., after the first call, repeated calls to this constructor return
the I<same> instance.  Note that the instance is instantiated at the time of
the first call, not before.

=back

=cut

sub new {
  my $cmm_class  = shift;
  my ($target_class, $name, $options, $global) = @_;

  check_opts([qw/ init hash direct-init v1_compat singleton /], $options);

  my $init_meth = $options->{init};
  $init_meth = 'init'
    if defined $init_meth and $init_meth eq '1';

  my $new;
  my $singleton;
  if ( $options->{hash} ) {
    $new = sub {
      my $self =
        $options->{singleton}                            ?
          ($singleton || ($singleton = bless {}, $_[0])) :
          (ref ($_[0]) ? $_[0] : bless {}, $_[0])        ;
      my $class = ref $self || $self;

      my %args;
      if ( @_ == 2 and ref($_[1]) eq 'HASH' ) {
        %args = %{ $_[1] };
      } elsif ( @_ % 2 ) {
        %args = @_[1..$#_];
      } else {
        die "Odd number of arguments for $name\n";
      }

      foreach (keys %args) {
        my $assign = $cmm_class->_class_comp_assign($class, $_);
        if ( defined $assign and my $setter = $class->can($assign) ) {
          $setter->($self, $args{$_});
        } else {
          $self->$_($args{$_});
        }
      }
      $self->$init_meth(@_[1..$#_])
        if $init_meth;

      $self;
    };
  } elsif ( $init_meth ) {
    $new = sub {
      my $class = ref $_[0] || $_[0];
      my $self =
        $options->{singleton}                              ?
          ($singleton || ($singleton = bless +{}, $class)) :
          bless(+{}, $class)                               ;
      $self->$init_meth(@_[1..$#_]);
      $self;
    };
  } elsif ( $options->{'direct-init'} ) {
    # This is here purely for v1 compatibility.  It can be trivially
    # implemented with -init, so is not explicitly supported for V2.
    $new = sub {
      my $class = ref $_[0] || $_[0];
      bless +{@_[1..$#_]}, $class;
    };
  } else {
    $new = sub {
      my $class = ref $_[0] || $_[0];
      $options->{singleton}                              ?
        ($singleton || ($singleton = bless +{}, $class)) :
        bless(+{}, $class)                               ;
    };
  }

  return +{ '*' => $new,
          };
}

# ----------------------------------------------------------------------------

=head2 abstract

  use Class::MethodMaker
    [ abstract => [ qw / foo bar baz / ] ];

This creates a number of methods that will die if called.  This is intended to
support the use of abstract methods, that must be overidden in a useful
subclass.

=cut

sub abstract {
  my $class = shift;
  my ($tclass, $name, $options, $global) = @_;

  my %known_options = map {; $_ => 1 } qw( v1_compat
                                         );
  if ( my @bad_opt = grep ! exists $known_options{$_}, keys %$options ) {
    my $prefix = 'Option' . (@bad_opt > 1 ? 's' : '');
    croak("$prefix not recognized for attribute type abstract: ",
          join(', ', @bad_opt), "\n");
  }

  return +{ '*' => sub {
              my ($self) = @_;
              my $cclass = ref $self;
              die <<"END";
Cannot invoke abstract method '${tclass}::${name}', called from '$cclass'.
END
            },
    };
}

# ----------------------------------------------------------------------------

=head2 copy

  use Class::MethodMaker
    [ copy => [qw/ shallow -deep deep /] ];

This creates method that produce a copy of self.  The copy is a by default a
I<shallow> copy; any references will be shared by the instance upon which the
method is called and the returned newborn.  One option is taken, C<-deep>,
which causes the method to create I<deep> copies instead (i.e., references are
copied recursively).

B<Implementation Note:>

Deep copies are performed using the C<Storable> module if available, else
C<Data::Dumper>.  The C<Storable> module is liable to be much quicker.
However, this implementation note is not an API specification: the
implementation details are open to change in a future version as faster/better
ways of performing a deep copy become available.

Note that deep copying does not currently support the copying of coderefs,
ties or XS-based objects.

=cut

sub copy {
  my $class = shift;
  my ($tclass, $name, $options, $global) = @_;

  check_opts([qw/ v1_compat deep /], $options);

  if ( $options->{deep} ) {
    eval 'use Storable;';
    eval 'use Data::Dumper;' if $@;
    die("Couldn't find required Data::Dumper module for deep copying: $@\n",
        "(which is odd, 'cause it's part of the core...\n")
      if $@;
    return +{ '*' => sub {
                my $self = shift; my $class = ref $self;

                if ( Storable->VERSION ) {
                  return Storable::dclone $self;
                } else {
                  my $copy;
                  eval Data::Dumper->Dump([$self],['copy']);
                  return $copy;
                }
              },
            };
  } else {
    return +{ '*' => sub {
                my $self = shift; my $class = ref $self;
                return bless { %$self }, $class;
              },
            };
  }
}

# ----------------------------------------------------------------------------

# This supplied for V1 compatiblity only

my (%BooleanPos, %BooleanFields);

sub _boolean {
  my $class = shift;
  my ($tclass, $name, $options, $global) = @_;

  check_opts([qw/ v1_compat /], $options);

  my $bstore = join '__', $tclass, 'boolean';

  $BooleanFields{$tclass} ||= [];
  my $boolean_fields = $BooleanFields{$tclass};

  my $bfp = $BooleanPos{$tclass}++;
  # $boolean_pos a global declared at top of file. We need to make a local
  # copy because it will be captured in the closure and if we capture the
  # global version the changes to it will effect all the closures. (Note also
  # that it's value is reset with each call to import_into_class.)
  push @$boolean_fields, $name;
  # $boolean_fields is also declared up above. It is used to store a list of
  # the names of all the bit fields.

  return +{
           'bits' => sub {
             my ($self, $new) = @_;
             defined $new and $self->{$bstore} = $new;
             $self->{$bstore};
           },

           'bit_fields' => sub { @$boolean_fields; },

           'bit_dump' => sub {
             my ($self) = @_;
             map { ($_, $self->$_()) } @$boolean_fields;
           },

           '*' => sub {
             my ($self, $on_off) = @_;
             defined $self->{$bstore} or $self->{$bstore} = "";
             if (defined $on_off) {
               vec($self->{$bstore}, $bfp, 1) = $on_off ? 1 : 0;
             }
             vec($self->{$bstore}, $bfp, 1);
           },

           '*_set' => sub {
             my ($self) = @_;
             $self->$name(1);
           },

           '*_clear' => sub {
             my ($self) = @_;
             $self->$name(0);
           },
          };
}

=head1 AUTHOR

Martyn J. Pearce <fluffy@cpan.org>

=cut
