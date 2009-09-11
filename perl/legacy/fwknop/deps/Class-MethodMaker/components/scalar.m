# (X)Emacs mode: -*- cperl -*-

# This file is preprocessed by cmmg.pl .  Subs are sought, as 'sub name {' (at
# a line begin) until '}' at a line begin.  Optional POD documentation may
# precede, if started with =head (and ended with =cut).  Blank lines &
# comments in between will be silently ignored, and anything else will be
# noisily ignored.

# -------------------------------------

=head1 NAME

Class::Method::scalar - Create methods for handling a scalar value.

=head1 SYNOPSIS

  package MyClass;
  use Class::MethodMaker
    [ scalar => [qw/ a -static s /]];

  sub new {
    my $class = shift;
    bless {}, $class;
  }

  package main;

  my $m = MyClass->new;
  my $a, $x;

  $a = $m->a;       # *undef*
  $x = $m->a_isset; # false
  $a = $m->a(1);    # 1
  $m->a(3);
  $x = $m->a_isset; # true
  $a = $m->a;       # 3
  $a = $m->a(5);     # 5;
  $m->a_reset;
  $x = $m->a_isset; # false

=head1 DESCRIPTION

Creates methods to handle array values in an object.  For a component named
C<x>, by default creates methods C<x>, C<x_reset>, C<x_isset>, C<x_clear>.

=cut


sub scalar {
  my $class  = shift;
  my ($target_class, $name, $options, $global) = @_;

  # options check ---------------------

  Class::MethodMaker::Engine::check_opts([qw/ static type typex forward
                                              default default_ctor
                                              read_cb store_cb
                                              tie_class tie_args
                                              key_create
                                              v1_compat v1_object
                                              _value_list
                                              /], $options);
  # type option
  my $type = $options->{type};
  croak "argument to -type ($type) must be a simple value\n"
    unless ! ref $type;

  # forward option
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

  # default options
  my ($default, $dctor, $default_defined, $v1object);
  if ( exists $options->{default} ) {
    croak("Cannot specify both default & default_ctor options to scalar ",
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
      $v1object = $options->{v1_object}
        if $options->{v1_compat};
    } else {
      $dctor = $options->{default_ctor};
      croak(sprintf( "Argument to default_ctor must be a simple value or a code ref " .
                     " (attribute $name) (got '%s')\n", ref $dctor ) )
        if ! UNIVERSAL::isa($dctor, 'CODE');
    }
    $default_defined = 1;
  }

  # tie options
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

  # V1 Compatibility
  my ($list, $key_create) = @{$options}{qw/ _value_list key_create/}
    if exists $options->{_value_list};

  # the method definitions ------------
  %%STORDECL%%

  # Predefine keys for subs we always want to exist (because they're
  # referenced by other subs)
  my %names = map {; $_ => undef } qw( * );

=pod

Methods available are:

=cut

  my %methods =

=pod

=head3 C<*>

  $m->a(3);
  $a = $m->a;       # 3
  $a = $m->a(5);     # 5;

I<Created by default>.  If an argument is provided, the component is set to
that value.  The method returns the value of the component (after assignment
to a provided value, if appropriate).

=cut

    ( '*'        => sub : method {
                      if ( @_ == 1 ) {
                        %%V1COMPAT_ON%%
                        if ( $v1object and ! exists $_[0]->{$name} ) {
                          %%STORAGE%% = $dctor->();
                        }
                        %%V1COMPAT_OFF%%
                        %%DEFCHECK$%%
                        %%READ0(%%STORAGE%%)%%
                      } else {
                        %%STORE($_[1],$v)%%                  %%V2ONLY%%
                        %%V1COMPAT_ON%%
                        %%STORE($_[1],$v,@_[1..$#_])%%
                        unless ( $v1object ) {
                          %%ASGNCHK$(%%IFSTORE($v,$_[1])%%)%%
                        }
                        %%V1COMPAT_OFF%%
                        %%ASGNCHK$(%%IFSTORE($v,$_[1])%%)%%  %%V2ONLY%%
                        %%STORAGE%% = %%IFSTORE($v,$_[1])%%; %%V2ONLY%%
                        %%V1COMPAT_ON%%
                        if ( $v1object ) {
                          if ( ref $_[1] and UNIVERSAL::isa($_[1], $type) ) {
                            %%STORAGE%% = $_[1];
                          } else {
                            %%STORAGE%% = $dctor->(@_[1..$#_]);
                          }
                        } else {
                          %%STORAGE%% = %%IFSTORE($v,$_[1])%%
                        }
                        %%V1COMPAT_OFF%%
                        %%READ1(%%STORAGE%%)%%
                      }
                    },

=pod

=head3 C<*_reset>

  $m->a_reset;

I<Created by default>.  Resets the component back to its default.  Normally,
this means that C<*_isset> will return false, and C<*> will return undef.  If
C<-default> is in effect, then the component will be set to the default value,
and C<*_isset> will return true.  If C<-default_ctor> is in effect, then the
default subr will be invoked, and its return value used to set the value of
the component, and C<*_isset> will return true.

B<Advanced Note>: actually, defaults are assigned as needed: typically, the
next time a the value of a component is read.

=cut

      '*_reset'  => sub : method {
                      delete %%STORAGE%%;
                    },

=pod

=head3 C<*_isset>

  print $m->a_isset ? "true" : "false";

I<Created by default>.  Whether the component is currently set.  This is
different from being defined; initially, the component is not set (and if
read, will return undef); it can be set to undef (which is a set value, which
also returns undef).  Having been set, the only way to unset the component is
with <*_reset>.

If a default value is in effect, then <*_isset> will always return true.

=cut

      '*_isset'  => ( $default_defined      ?
                      sub : method { 1 }    :
                      sub : method {
                        exists %%STORAGE%%;
                      }
                    ),

=pod

=head3 C<*_clear>

  $m->a(5);
  $a = $m->a;       # 5
  $x = $m->a_isset; # true
  $m->a_clear;
  $a = $m->a;       # *undef*
  $x = $m->a_isset; # true

I<Created by default>.  A shorthand for setting to undef.  Note that the
component will be set to undef, not reset, so C<*_isset> will return true.

=cut

      '*_clear' => sub : method {
                      my $x = $names{'*'};
                      $_[0]->$x(undef);
                    },

=pod

=head3 C<*_get>

  package MyClass;
  use Class::MethodMaker
    [ scalar => [{'*_get' => '*_get'}, 'a'],
      new    => new, ];

  package main;
  my $m = MyClass->new;
  $m->a(3);
  $a = $m->a_get;     # 3
  $a = $m->a_get(5);  # 3; ignores argument
  $a = $m->a_get(5);  # 3; unchanged by previous call

I<Created on request>.  Retrieves the value of the component without setting
(ignores any arguments passed).

=cut

      '!*_get'   => sub : method {
                      my $x = $names{'*'};
                      return $_[0]->$x();
                    },

=pod

=head3 C<*_set>

  package MyClass;
  use Class::MethodMaker
    [ scalar => [{'*_set' => '*_set'}, 'a'],
      new    => new, ];

  package main;
  my $m = MyClass->new;
  $m->a(3);
  $a = $m->a_set;     # *undef*
  $a = $m->a_set(5);  # *undef*; value is set but not returned
  $a = $m->a;         # 5

I<Created on request>.  Sets the component to the first argument (or undef if
no argument provided).  Returns no value.

=cut

      '!*_set'   => sub : method {
                      my $x = $names{'*'};
                      $_[0]->$x($_[1]);
                      return;
                    },

       # this is here for V1 compatiblity only
       '!*_find' => sub : method {
                      my ($self, @args) = @_;
                      if (scalar @args) {
                        if ( $key_create ) {
                          $self->new->$name($_)
                            for grep ! exists $list->{$_}, @args;
                        }
                        return @{$list}{@args};
                      } else {
                        return $list;
                      }
                    },

       %%IMPORT(CommonMethods)%%

       # forward methods
       map({; my $f = $_;
            $_ =>
              sub : method {
                my $x = $names{'*'};
                $_[0]->$x()->$f(@_[1..$#_]);
              }
           } @forward),
    );

  return \%methods, \%names;
}
