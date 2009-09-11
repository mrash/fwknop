#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package X;

use Class::MethodMaker
  code => [ qw / a b / ],
  code => 'c';
sub new { bless {}, shift; }

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

sub foo { "foo" };
sub bar { $_[0] };
sub baz { $_[2]++; $_[0] + $_[1] };
my $baz_called = 0;
my $baz1 = sub { $_[2]++; $_[0] + $_[1] };
my $baz2 = bless sub { $baz_called++; }, 'baz';
my $o = new X;

TEST { 1 };
#TEST { eval { $o->a }; !$@ }; # Ooops! this is broken at the moment.
TEST { $o->a(\&foo) };
TEST { $o->a eq 'foo' };
TEST { $o->b(\&bar) };
TEST { $o->b('xxx') eq 'xxx' };
TEST { $o->c(sub { "baz" } ) };
TEST { $o->c eq 'baz' };
# Not stored because it's blessed
TEST { $o->c($baz2) };
TEST { $o->c eq 'baz' };
TEST { $baz_called == 0 };
TEST { $o->c($baz1) };
my ($a, $b, $c, $d) = (4, 5, 6);
TEST { $d = $o->c($a, $b, $c) };
TEST { $d == 9 };
# is copied by value, not aliased
TEST { $c == 6 };

exit 0;

