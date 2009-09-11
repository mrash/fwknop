#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package X;

use ExtUtils::testlib;

use Class::MethodMaker
  new => 'new',
  new_with_args => 'new_with_args',
  new_with_init => 'new_with_init',
  new_hash_init => 'new_hash_init',
  get_set => 'toto'
  ;

my $init_called;
my @args_in_init;
my $foo_called;
my $bar_called;

sub init {
  my ($self, @args) = @_;
  $init_called++;
  @args_in_init = @args;
}

sub foo {
  my ($self, $new) = @_;
  defined $new and $self->{'foo'} = $new;
  $foo_called = 1;
  $self->{'foo'};
}

sub bar {
  my ($self, $new) = @_;
  defined $new and $self->{'bar'} = $new;
  $bar_called = 1;
  $self->{'bar'};
}

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

TEST { 1 };

# Regular new
TEST { $o = new X; };
TEST { ref $o eq 'X'; };

# new_with_init
my @args = (1, 2, 3);
TEST { $o = X->new_with_init(@args) };
TEST { ref $o eq 'X'; };
TEST {  $#args_in_init == $#args };
TEST {
  for (0..$#args) { $args_in_init[$_] == $args[$_] or return 0; }
  return 1;
};

# new_hash_init
TEST { $o = X->new_hash_init( 'foo' => 123, 'bar' => 456 ) };
TEST { ref $o eq 'X'; };
TEST { $foo_called };
TEST { $bar_called };
TEST { $o->foo == 123 };
TEST { $o->bar == 456 };

# new_hash_init (taking hashref)
TEST { $o = X->new_hash_init({ 'foo' => 123, 'bar' => 456 }) };
TEST { ref $o eq 'X'; };
TEST { $foo_called };
TEST { $bar_called };
TEST { $o->foo == 123 };
TEST { $o->bar == 456 };

# new_with_args
TEST { $o = X->new_with_args(toto => '3');};
TEST { $o->toto eq '3'};

exit 0;

