#!/usr/local/bin/perl

package X;


use Class::MethodMaker
  counter => [ qw / a b / ],
  abstract => 'c';

sub new { bless {}, shift; }

package main;
use lib qw ( ./t );
use test_v1;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new X;

TEST { 1 };
TEST { $o->a == 0 };
TEST { $o->a == 0 };
TEST { $o->a_incr == 1 };
TEST { $o->a_incr == 2 };
TEST { $o->a == 2 };
TEST { eval { $o->a_reset }; ! length $@ };
TEST { $o->a == 0 };
TEST { $o->a_incr(2) == 2 };
TEST { $o->a_incr(3) == 5 };
TEST { $o->a_incr    == 6 };

exit 0;

