#!/usr/local/bin/perl

package X;

use Class::MethodMaker
  key_with_create => [ qw / a b / ],
  key_with_create => 'c';

sub new { bless {}, shift; }

package main;
use lib qw ( ./t );
use test_v1;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new X;
my $o2 = new X;

TEST { 1 };

TEST { $o->a(123) };
TEST { $o->a == 123 };
TEST { X->find_a(123) eq $o };
TEST {
  $o2->a(456);
  my @f = X->find_a(123, 456);
  $f[0] eq $o or return 0;
  $f[1] eq $o2 or return 0;
};

TEST { $o->a('foo') };
TEST { X->find_a(123) ne $o };
TEST { X->find_a('foo') eq $o };
TEST { $o->a(456) };
TEST { X->find_a(456) eq $o };

my $h;
$o2->a(789);
TEST { $h = X->find_a };
TEST { ref $h eq 'HASH' };
TEST { scalar keys %$h == 3 };
TEST { $h->{456} eq $o };
TEST { $h->{789} eq $o2 };

TEST { ! $o2->clear_a };

my $o3;
TEST { $o3 = X->find_a('baz') };
TEST { ref $o3 eq 'X' };

exit 0;

