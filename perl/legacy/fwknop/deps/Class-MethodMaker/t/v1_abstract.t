#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package X;


use Class::MethodMaker
  abstract => [ qw / a b / ],
  abstract => 'c';

sub new { bless {}, shift; }

package Y;
use vars '@ISA';
@ISA = qw ( X );

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new Y;

TEST { 1 };
TEST {
  eval { $o->a } ;
  $@ =~ /\QCan't locate abstract method "a" declared in "X" via "Y"./ 
    or
  $@ =~ /\QCan't locate abstract method "a" declared in "X", called from "Y"./
    or
  $@ =~ /\QCannot invoke abstract method 'X::a', called from 'Y'./;
};

exit 0;

