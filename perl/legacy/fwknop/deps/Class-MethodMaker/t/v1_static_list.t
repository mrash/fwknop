#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package X;

use Class::MethodMaker
  static_list => [ qw / a b / ],
  static_list => 'c';

sub new { bless {}, shift; }

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

use Data::Dumper;

my $o = new X;
my $o2 = new X;

# 1--6
TEST { 1 };
TEST { ! scalar @{$o->a} };
TEST { $o->a_push(123, 456) };
TEST { $o->a_unshift('baz') };
TEST { $o->a_pop == 456 };
TEST { $o->a_shift eq 'baz' };

#7--8
TEST { $o->b_push(123, 'foo', [ qw / a b c / ], 'bar') };
TEST {
  my @l = $o->b;
  print STDERR Data::Dumper->Dump([\@l],['l'])
    if exists $ENV{TEST_DEBUG} && $ENV{TEST_DEBUG};
  $l[0] == 123 and
  $l[1] eq 'foo' and
  $l[2]->[0] eq 'a' and
  $l[2]->[1] eq 'b' and
  $l[2]->[2] eq 'c' and
  $l[3] eq 'bar'
};

# 9
TEST {
  $o->b_splice(1, 2, 'baz');
  my @l = $o->b;
  print STDERR Data::Dumper->Dump([\@l],['l'])
    if exists $ENV{TEST_DEBUG} && $ENV{TEST_DEBUG};
  $l[0] == 123 and
  $l[1] eq 'baz' and
  $l[2] eq 'bar'
};

# 10--12
TEST { ref $o->b_ref eq 'ARRAY' };
TEST { ! scalar $o->b_clear };
TEST { ! scalar @{$o->b} };

$o->b_unshift(qw/ a b c /);
my @x = $o->b_index (2, 1, 1, 2);
# 13--15
TEST { @x == 4 };
TEST { $x[0] eq 'c' and $x[3] eq 'c' };
TEST { $x[1] eq 'b' and $x[2] eq 'b' };

$o->b_set ( 1 => 'd' );
@x = $o->b;
# 16--19
TEST { @x == 3 };
TEST { $x[0] eq 'a' };
TEST { $x[1] eq 'd' };
TEST { $x[2] eq 'c' };

eval {
  $o->b_set ( 0 => 'e', 1 );
};
# 20--21
TEST { $@ };
TEST { ($o->b)[0] eq ($o2->b)[0] };

eval {
  $o->b ( 'e' );
};
# 22--26
TEST { ! $@ };
TEST { ($o->b)[0] eq 'e' };
TEST { (my @a = $o->b) == 1 };
TEST { ($o2->b)[0] eq 'e' };
TEST { (my @a = $o2->b) == 1 };
exit 0;

