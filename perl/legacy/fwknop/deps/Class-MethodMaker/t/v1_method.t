#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package X;

use Class::MethodMaker
  method => [ qw / a b / ],
  method => 'c';
sub new { bless {}, shift; }

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

sub foo { "foo" };
sub bar { $_[0] };
my $o = new X;

TEST { 1 };
#TEST { eval { $o->a }; !$@ }; # Ooops! this is broken at the moment.
TEST { $o->a(\&foo) };
TEST { $o->a eq 'foo' };
TEST { $o->b(\&bar) };
TEST { $o->b('xxx') eq $o };
TEST { $o->c(sub { "baz" } ) };
TEST { $o->c eq 'baz' };

exit 0;

