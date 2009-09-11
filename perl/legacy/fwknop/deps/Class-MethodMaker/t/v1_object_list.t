#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package Y;
my $count = 0;
sub new { bless { id => $count++ }, shift; }
sub id { shift->{id}; }

package X;

use Class::MethodMaker
  object_list  => [
		   'Y' => { slot => 'a', comp_mthds => 'id' },
		  ];

sub new { bless {}, shift; }
my $o = new X;

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

# 1
TEST { 1 };

# 2-3
TEST { $o->a_push (Y->new) };
TEST { $o->a_push (Y->new) };
# 4-6
TEST { $o->a_pop->id == 1  };
TEST { $o->a_push (Y->new) };
TEST { @b = $o->a; @b == 2 };
# 7-9
TEST { join (' ', $o->id) eq '0 2' };
TEST { $a = 1; for ($o->a) { $a &&= ( ref ($_) eq 'Y' ) }; $a };
TEST { $o->a_shift->id == 0 };
# 10-12
TEST { $o->a_unshift ( Y->new ) };
TEST { @b = $o->a; @b == 2 };
TEST { $a = 1; for ($o->a) { $a &&= ( ref ($_) eq 'Y' ) }; $a };
# 13-15
TEST { join (' ', $o->id) eq '3 2' };
TEST { ref($o->a_index(0)) eq 'Y' };
TEST { $o->a_set(0 => Y->new); 1 };
# 16-17
TEST { $o->a_index(0)->id == 4};
TEST { @b = $o->a; @b == 2 };

# 18
TEST { $o->a_clear; $o->a_count == 0 };

# Backwards compatibility test
# 19-21
TEST { $o->push_a (Y->new) };
TEST { $o->push_a (Y->new) };
TEST { $o->pop_a->id == 6 };
# 22-24
TEST { $o->push_a (Y->new) };
TEST { @b = $o->a; @b == 2 };
TEST { join (' ', $o->id) eq '5 7' };
# 25-27
TEST { $a = 1; for ($o->a) { $a &&= ( ref ($_) eq 'Y' ) }; $a };
TEST { $o->shift_a->id == 5 };
TEST { $o->unshift_a ( Y->new ) };
# 28-30
TEST { @b = $o->a; @b == 2 };
TEST { $a = 1; for ($o->a) { $a &&= ( ref ($_) eq 'Y' ) }; $a };
TEST { join (' ', $o->id) eq '8 7' };
# 31-33
TEST { ref($o->index_a(0)) eq 'Y' };
TEST { $o->set_a(0 => Y->new); 1 };
TEST { $o->a_index(0)->id == 9};
# 34
TEST { @b = $o->a; @b == 2 };

exit 0;

