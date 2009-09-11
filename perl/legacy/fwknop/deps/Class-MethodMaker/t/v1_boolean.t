#!/usr/local/bin/perl

package X;

use Class::MethodMaker
  boolean => [ qw / a b c d / ],
  boolean => 'e';

sub new { bless {}, shift; }

package Y;

use base 'X';

use Class::MethodMaker
  boolean => [ qw / m n / ];

sub new { bless {}, shift; }

package main;
use lib qw ( ./t );
use test_v1;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new X;

TEST { 1 };

TEST { ! $o->a };
TEST { ! $o->b };
TEST { ! $o->c };
TEST { ! $o->d };
TEST { ! $o->e };

TEST { $o->a(1); };
TEST { $o->a };

TEST { $o->set_a };
TEST { $o->a };

TEST { ! $o->a(0); };
TEST { ! $o->a };

TEST { ! $o->clear_a; };
TEST { ! $o->a };

my @f;
TEST { @f = $o->bit_fields };
TEST {
  $f[0] eq 'a' and
  $f[1] eq 'b' and
  $f[2] eq 'c' and
  $f[3] eq 'd' and
  $f[4] eq 'e'
};

TEST {
  $o->clear_a; $o->clear_b; $o->set_c;
  $o->set_d; $o->clear_e;
  my %f = $o->bit_dump;
  $f{'a'} == 0 and $f{'a'} == $o->a and
  $f{'b'} == 0 and $f{'b'} == $o->b and
  $f{'c'} == 1 and $f{'c'} == $o->c and
  $f{'d'} == 1 and $f{'d'} == $o->d and
  $f{'e'} == 0 and $f{'e'} == $o->e
};

my $y = new Y;
$y->set_a;
$y->clear_m;

TEST {
  $y->a;
};

TEST {
  ! $y->m;
};

exit 0;

