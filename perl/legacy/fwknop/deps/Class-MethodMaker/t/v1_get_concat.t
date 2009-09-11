#!/usr/local/bin/perl

package X;

use Class::MethodMaker 
  get_concat => 'x',
  get_concat => {'name' => 'y', 'join' => "\t"},
  ;

sub new { bless {}, shift; }

package main;
use lib qw ( ./t );
use test_v1;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new X;

TEST { 1 };
TEST { ! defined $o->x };
TEST { $o->x('foo') };
TEST { $o->x eq 'foo' };
TEST { $o->x('bar') };
TEST { $o->x eq 'foobar' };
TEST { ! defined $o->clear_x };
TEST { ! defined $o->x };

TEST { ! defined $o->y };
TEST { $o->y ('one') };
TEST { $o->y eq 'one' };
TEST { $o->y ('two') };
TEST { $o->y eq "one\ttwo" };

exit 0;

