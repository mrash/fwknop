#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package X;

use Class::MethodMaker
  get_set    => [qw/ a b /],
  copy       => 'copy',
  deep_copy  => 'deeply';

sub new { bless {}, shift; }

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new X;

# 1--8

TEST { 1 };
TEST { $o->a ('foo') eq 'foo' };
TEST { $c = $o->copy; };
TEST { $c->a eq 'foo' };
TEST { $c->a ('bar') eq 'bar' };
TEST { $o->a eq 'foo' };
TEST { $o->a ('baz') eq 'baz' };
TEST { $c->a eq 'bar' };

# 9--: deep copying

my $o2 = new X;
my $o3;

TEST { $o2->a($o) };
TEST { $o2->a == $o };
TEST { $o2->a->a eq 'baz' };
TEST { $o3 = $o2->deeply; };
TEST { $o3->a->a eq 'baz' };
TEST { $o->a('bar') };
TEST { $o->a eq 'bar' };
TEST { $o2->a->a eq 'bar' };
TEST { $o3->a->a eq 'baz' };


exit 0;

