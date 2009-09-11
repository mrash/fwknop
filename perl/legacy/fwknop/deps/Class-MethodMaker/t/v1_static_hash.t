#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package X;

use Class::MethodMaker
  static_hash => [ qw / a b / ],
  static_hash => 'c';

sub new { bless {}, shift; }

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new X;
my $o2 = new X;

TEST { 1 };
TEST { ! scalar keys %{$o->a} };
TEST { ! defined $o->a('foo') };
TEST { $o->a('foo', 'baz') };
TEST { $o->a('foo') eq 'baz' };
TEST { $o->a('bar', 'baz2') };
TEST {
  my @l = $o->a([qw / foo bar / ]);
  $l[0] eq 'baz' and $l[1] eq 'baz2'
};

TEST { $o->a(qw / a b c d / ) };
TEST {
  my %h = $o->a;
  my @l = sort keys %h;
  $l[0] eq 'a' and
  $l[1] eq 'bar' and
  $l[2] eq 'c' and
  $l[3] eq 'foo'
};

TEST {
  my %h=('w' => 'x', 'y' => 'z');
  my $rh = \%h;
  my $r = $o->a($rh);
};

TEST {
  my @l = sort $o->a_keys;
  $l[0] eq 'a' and
  $l[1] eq 'bar' and
  $l[2] eq 'c' and
  $l[3] eq 'foo' and
  $l[4] eq 'w' and
  $l[5] eq 'y'
};

TEST {
  my @l = sort $o->a_values;
  $l[0] eq 'b' and
  $l[1] eq 'baz' and
  $l[2] eq 'baz2' and
  $l[3] eq 'd' and
  $l[4] eq 'x' and
  $l[5] eq 'z'
};

TEST { $o->b_tally(qw / a b c a b a d / ); };
TEST {
  my %h = $o->b;
  $h{'a'} == 3 and
  $h{'b'} == 2 and
  $h{'c'} == 1 and
  $h{'d'} == 1
};

TEST { ! defined $o->c('foo') };
TEST { defined $o->c };

TEST {
  my @a  = $o->a;
  my @a2 = $o2->a;
  (@a == @a2) &&
    ! grep $a[$_] ne $a2[$_], 0..$#a;
};

exit 0;
