#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package XXX;

use Class::MethodMaker
    new_hash_with_init => 'new',
    get_set => [ qw/foo bar baz/ ];

sub init {
	my $self = shift;
	$self->bar(666);
	$self->baz(42);
}

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

# test the classes themselves

my $obj = XXX->new(foo => 7, bar => 13);
# 1--4
TEST { $obj->isa('XXX'); };
TEST { $obj->foo == 7; };
TEST { $obj->bar == 666; };
TEST { $obj->baz == 42; };
