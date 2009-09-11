#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package X;

use Class::MethodMaker
  hash => [ qw / a b / ],
  hash => 'c',
  new_hash_init => 'new';


package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new X;

# 1--7
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

# 8--9
TEST { $o->a(qw / a b c d / ) };
TEST {
  my @l = sort keys %{$o->a};
  $l[0] eq 'a' and
  $l[1] eq 'bar' and
  $l[2] eq 'c' and
  $l[3] eq 'foo'
};

# 10
TEST {
  my %h=('w' => 'x', 'y' => 'z');
  $o->a(\%h);
};

# 11
TEST {
  my @l = sort $o->a_keys;
  $l[0] eq 'a' and
  $l[1] eq 'bar' and
  $l[2] eq 'c' and
  $l[3] eq 'foo'and
  $l[4] eq 'w' and
  $l[5] eq 'y'
};

#12
TEST {
  my @l = sort $o->a_values;
  $l[0] eq 'b' and
  $l[1] eq 'baz' and
  $l[2] eq 'baz2' and
  $l[3] eq 'd'and
  $l[4] eq 'x' and
  $l[5] eq 'z'
};

# 13--14
TEST { $o->b_tally(qw / a b c a b a d / ); };
TEST {
  my %h = $o->b;
  $h{'a'} == 3 and
  $h{'b'} == 2 and
  $h{'c'} == 1 and
  $h{'d'} == 1
};

# 15--19
TEST { $o->c('foo', 'bar') };
TEST { $o->c('foo') eq 'bar' };
TEST { 1 };
TEST { $o->c_delete('foo'); ! defined $o->c('foo') };
TEST { $o->c };

#20
TEST {
  $o->c(qw / a b c d e f /);
  my %h = $o->c;
  $h{'a'} eq 'b' and
  $h{'c'} eq 'd' and
  $h{'e'} eq 'f'
};

#21
TEST {
  $o->c_delete(qw / a c /);
  my %h = $o->c;
  $h{'e'} eq 'f'
};

#22
TEST {
  my @l = sort keys %{$o->a};
  $l[0] eq 'a' and
  $l[1] eq 'bar' and
  $l[2] eq 'c' and
  $l[3] eq 'foo' and
  $l[4] eq 'w' and
  $l[5] eq 'y'
};

#23
TEST {
  $o->a_clear;
  my @a_keys = $o->a_keys;
  @a_keys == 0;
};

#24
$o->a ('a' => 1);
my @l = keys %{$o->a};
TEST {
  $l[0] eq 'a';
};

#25
TEST {
  @l == 1;
};

#26
TEST {
  my $x = $o->a;
  my $y = $o->a;
  $x == $y;
};

#27
TEST {
  my $x = X->new(a => +{a => 1, b => 2});
};

exit 0;

