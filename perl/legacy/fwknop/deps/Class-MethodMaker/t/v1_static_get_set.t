#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package X;

use Class::MethodMaker
  get_set => [ qw / -static a b / ],
  static_get_set => 'c';

sub new { bless {}, shift; }

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new X;
my $o2 = new X;

# 1--7
TEST { 1 };
TEST { ! defined $o->a };
TEST { $o->a(123) };
TEST { $o->a == 123 };
TEST { $o2->a == 123 };
TEST { ! defined $o2->clear_a };
TEST { ! defined $o->a };

# 8--13
TEST { ! defined $o->b };
TEST { $o->b('hello world') };
TEST { $o->b eq 'hello world' };
TEST { $o2->b eq 'hello world' };
TEST { ! defined $o2->clear_b };
TEST { ! defined $o->b };

my $foo = 'this';
# 14--15
TEST { ! defined $o->c };
TEST { $o->c(\$foo) };

$foo = 'that';

# 16--22
TEST { $o->c eq \$foo };
TEST { $o2->c eq \$foo };
TEST { ${$o->c} eq ${$o2->c}};
TEST { ${$o->c} eq 'that'};
TEST { ${$o->c} eq 'that'};
TEST { ! defined $o2->clear_c };
TEST { ! defined $o->c };

exit 0;

