# (X)Emacs mode: -*- cperl -*-

package Class::MethodMaker::OptExt;

=head1 NAME

Class::MethodMaker::OptExt - Constants for C::MM's option extension mechanism

=head1 SYNOPSIS

This class is internal to Class::MethodMaker and should not be used by any
clients.  It is B<not> part of the public API.

=head1 DESCRIPTION

This class contains the constants used by Class::MethodMaker to determine the
names of its methods dependent upon options invoked.

=cut

# ----------------------------------------------------------------------------

# Pragmas -----------------------------

require 5.006;
use strict;
use warnings;

# Inheritance -------------------------

use base qw( Exporter );
our @EXPORT_OK = qw( OPTEXT );

# Utility -----------------------------

use Carp qw( carp croak );

# ----------------------------------------------------------------------------

# CLASS METHODS --------------------------------------------------------------

# -------------------------------------
# CLASS CONSTANTS
# -------------------------------------

=head1 CLASS CONSTANTS

Z<>

=cut

use constant COMPONENT_TYPES => qw( scalar array hash );

# Max 8 codepoints else fix dereferencing in encode, below
use constant codepoints => [qw( refer decl
                                postac asgnchk
                                predefchk defchk
                                reset
                                read store )];
# codepoint_value is a map from codepoint to a unique power of two, used to
# check for illegal combinations of options
use constant codepoint_value => +{ map({codepoints->[$_]=>2**$_}
                                       0..$#{codepoints()})
                                 };
use constant cv_reverse      => +{ reverse %{codepoint_value()} };

=head2 OPTEXT

OPTEXT is a map from options that are implemented as method extensions to
the option parameters.

Parameter keys are:

=over 4

=item encode

code number (to allow the option combination to be encoded whilst keeping the
length of the subr name no more than 8 chars).  encode is required for all
opts (for determining method extension), and must be a power of two.

=item refer

Code for referring to storage (default: '$_[0]->{$name}').

=item decl

Code for declaring storage.

=item postac

Code to execute immediately after any assignment check --- for example, to
initialize storage if necessary

=item asgnchk

Code for checking assignments.

=item defchk

Code for default checking.

=item reset

Code to execute when resetting an element

=item read

Code to execute each time an value is read

=item store

Code to execute each time a value is stored

=back

=cut

# Defines Matrix
#
# codepoint->  refer decl postac asgnchk predefchk defchk reset read store
# option
#
# static         X    X
# type                              X
# default                                            X
# default_ctor                                       X
# tie_class                 X                X              X
# v1_compat
# read_cb                                                        X
# store_cb                                                             X

use constant OPTEXT => { DEFAULT => { refer     => '$_[0]->{$name}',
                                      decl      => '',
                                      postac    => '',
                                      asgnchk   => '',
                                      predefchk => '',
                                      defchk    => '',
                                      reset     => '',
                                      read      => ['__VALUE__', ''],
                                      store     => '',
                                    },

                        static =>  { encode  => 1,
                                     refer   => '$store[0]',
                                     decl    => 'my @store;',
                                    },
                        type   =>  { encode  => 2,
                                     asgnchk => <<'END',
for (__FOO__) {
  croak(sprintf("Incorrect type for attribute __ATTR__: %s\n" .
                "  : should be '%s' (or subclass thereof)\n",
                (defined($_)                                     ?
                 (ref($_) ? ref($_) : "plain value(-->$_<--)" )  :
                 '*undef*'
                ), $type))
    unless ! defined $_ or UNIVERSAL::isa($_, $type);
}
END
                                    },
                         default => { encode => 4,
                                      defchk => <<'END',
if ( ! exists %%STORAGE%% ) {
  %%ASGNCHK__SIGIL__($default)%%
  %%STORAGE%% = $default
}
END
                                    },
                         default_ctor => { encode => 8,
                                           defchk => <<'END',
if ( ! exists %%STORAGE%% ) {
  my $default = $dctor->($_[0]);
  %%ASGNCHK__SIGIL__($default)%%
  %%STORAGE%% = $default
}
END
                                         },
                         tie_class => { encode => 16,
                                        postac => <<'END',
tie %%STORAGE(__SIGIL__)%%, $tie_class, @tie_args
  unless exists %%STORAGE%%;
END
                                        predefchk => <<'END',
tie %%STORAGE(__SIGIL__)%%, $tie_class, @tie_args
  unless exists %%STORAGE%%;
END
                                        reset => <<'END',
untie %%STORAGE(__SIGIL__)%%;
END
                                      },
                         v1_compat => { encode => 32,
                                      },
                         read_cb => { encode => 64,
                                      read => [(<<'END') x 2],
{ # Encapsulate scope to avoid redefined $v issues
  my $v = __VALUE__;
  $v = $_->($_[0], $v)
    for @read_callbacks;
  $v;
}
END
                                    },
                         store_cb => { encode => 128,
                                       store =><<'END',
my __NAME__ = __VALUE__;
if ( exists %%STORAGE%% ) {
  my $old = %%STORAGE%%;
  __NAMEREF__ = $_->($_[0], __NAMEREF__, $name, $old)           %%V2ONLY%%
  __NAMEREF__ = $_->($_[0], __NAMEREF__, $name, $old, __ALL__)  %%V1COMPAT%%
    for @store_callbacks;
} else {
  __NAMEREF__ = $_->($_[0], __NAMEREF__, $name)                 %%V2ONLY%%
  __NAMEREF__ = $_->($_[0], __NAMEREF__, $name, undef, __ALL__) %%V1COMPAT%%
    for @store_callbacks;
}
END
                                    },
                        typex   =>  { encode  => 256,
                                     asgnchk => <<'END',
for (__FOO__) {
#   $_ += 0;
#  croak(sprintf("Incorrect type for attribute __ATTR__: %s\n" .
#                "  : should be '%s' (or subclass thereof)\n",
#                (defined($_)                                     ?
#                 (ref($_) ? ref($_) : "plain value(-->$_<--)" )  :
#                 '*undef*'
#                ), $typex))
#    unless ! defined $_ or UNIVERSAL::isa($_, $typex);
}
END
                                    },
                       };

# Single value representing the codepoints defined for each option
sub optdefvalue {
  my $class = shift;
  my ($option) = @_;

  my $code = OPTEXT->{$option};
  croak "Illegal option name: '$option'\n"
    unless defined $code;

  my $value = 0;
  for ( @{codepoints()} ) {
    $value |= codepoint_value->{$_}
      if exists $code->{$_};
  }

#  return split //, unpack "b9", chr($value >> 8) . chr($value & 255);
#print $value;
  return split //, unpack "b16", chr($value >> 8) .  chr($value & 255);
}

BEGIN {
  croak "No encode value found for type $_\n"
    for grep ! OPTEXT->{$_}->{encode}, grep $_ ne 'DEFAULT', keys %{OPTEXT()};
}

# -------------------------------------
# CLASS CONSTRUCTION
# -------------------------------------

# -------------------------------------
# CLASS COMPONENTS
# -------------------------------------

=head1 CLASS COMPONENTS

Z<>

=cut

# -------------------------------------
# CLASS HIGHER-LEVEL FUNCTIONS
# -------------------------------------

=head1 CLASS HIGHER-LEVEL FUNCTIONS

Z<>

=cut

=head2 encode

Take a set of options, return a two-letter code being the extension to add to
the method to incorporate the extensions, and a list (arrayref) of the
extensions represented.

=over 4

=item SYNOPSIS

  my ($ext, $opt) =
    Class::MethodMaker::OptExt->encode([qw( static type foobar )]);

=item ARGUMENTS

=over 4

=item options

The options to encode, as an arrayref of option names

=back

=item RETURNS

=over 4

=item ext

A code (string) to append to a methodname to represent the options used.

=item opts

The options represented by the ext .  This is generally a subset of the of
those provided in options, for not all general options are handled by an
encoded methodname.

=back

=back

=cut

sub encode {
  my $class = shift;
  my ($type, $options) = @_;

  {
    my @check;
    for my $opt (grep exists OPTEXT->{$_}, @$options) {
      my @v = $class->optdefvalue($opt);
      $check[$_] += $v[$_]
        for 0..$#v;
    }
    if ( grep $_ > 1, @check ) {
      local $" = ',';
      return;
    }
  }

  my $ext = '';
  my @optused;

  if ( grep $_ eq $type, COMPONENT_TYPES ) {
    my $value = 0;
    for (@$options) {
      push(@optused, $_), $value += OPTEXT->{$_}->{encode}
        if exists OPTEXT->{$_};
    }
    $ext = sprintf("%04x", $value);
  }

  return $ext, \@optused;
}

# -------------------------------------

sub option_names { grep $_ ne 'DEFAULT', keys %{OPTEXT()} }

sub optcode {
  my $class = shift;
  my ($codepoint, $options) = @_;

  my $code;
  for my $opt (grep exists OPTEXT->{$_}->{$codepoint}, @$options) {
    $code = OPTEXT->{$opt}->{$codepoint};
  }

  if ( ! defined $code ) {
    if ( exists OPTEXT->{DEFAULT}->{$codepoint} ) {
      $code = OPTEXT->{DEFAULT}->{$codepoint};
    } else {
      croak "Codepoint '$codepoint' not recognized\n";
    }
  }

  return $code;
}

# -------------------------------------

sub replace {
  my $class = shift;
  my ($st) = @_;
  my %replace;
    $replace{$_} = Class::MethodMaker::OptExt->optcode($_, $st)
        for @{Class::MethodMaker::OptExt->codepoints};
  return %replace;
}

# -------------------------------------
# CLASS HIGHER-LEVEL PROCEDURES
# -------------------------------------

=head1 CLASS HIGHER-LEVEL PROCEDURES

Z<>

=cut

# INSTANCE METHODS -----------------------------------------------------------

# -------------------------------------
# INSTANCE CONSTRUCTION
# -------------------------------------

=head1 INSTANCE CONSTRUCTION

Z<>

=cut

# -------------------------------------
# INSTANCE FINALIZATION
# -------------------------------------

# -------------------------------------
# INSTANCE COMPONENTS
# -------------------------------------

=head1 INSTANCE COMPONENTS

Z<>

=cut

# -------------------------------------
# INSTANCE HIGHER-LEVEL FUNCTIONS
# -------------------------------------

=head1 INSTANCE HIGHER-LEVEL FUNCTIONS

Z<>

=cut

# -------------------------------------
# INSTANCE HIGHER-LEVEL PROCEDURES
# -------------------------------------

=head1 INSTANCE HIGHER-LEVEL PROCEDURES

Z<>

=cut

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

Copyright (c) 2003 Martyn J. Pearce.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

Z<>

=cut

1; # keep require happy.

__END__
