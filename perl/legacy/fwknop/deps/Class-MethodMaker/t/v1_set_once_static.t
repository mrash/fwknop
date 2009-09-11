#!/usr/local/bin/perl

package X;

use Class::MethodMaker
  get_set  => [qw[ -set_once   -static foo ]],
  get_set  => [qw[ -static     -set_once bar ]],
  get_set  => [qw[ -static     -set_once_or_ignore ignore00 ]],
  get_set  => [qw[ -static     -set_once_or_warn warn00 ]],
  get_set  => [qw[ -static     -set_once_or_carp carp00 ]],
  get_set  => [qw[ -static     -set_once_or_myonce myonce00 ]],
  ;

sub new { bless {}, shift; }
sub myonce { die "myonce" };

package main;
use lib qw ( ./t );
use test_v1;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $a = new X;
my $b = new X;

# 1..6
TEST { 1 };
TEST { !defined $a->foo() };
TEST { $b->foo('x') eq 'x' };
TEST { $a->foo() eq 'x' };
TEST { eval{1}; eval{$a->foo('y')}; length($@) };
TEST { eval{1}; eval{$b->foo('y')}; length($@) };

# 7..12
TEST { 1 };
TEST { !defined $a->bar() };
TEST { $b->bar('x') eq 'x' };
TEST { $a->bar() eq 'x' };
TEST { eval{1}; eval{$a->bar('y')}; length($@) };
TEST { eval{1}; eval{$b->bar('y')}; length($@) };

# trigger ANOTHER set on all values
my $w; # 1 if a warn() of sorts was called.
$SIG{__WARN__} = sub { $w=1; die(@_) };

# 13..20
TEST { 1 };
TEST { !defined $a->warn00() };
TEST { $b->warn00('a') eq 'a' };
TEST { $a->warn00() eq 'a' };
TEST { eval{$w=0;1}; eval{$a->warn00('b')}; $w==1 && length($@) };
TEST { eval{$w=0;1}; eval{$b->warn00('b')}; $w==1 && length($@) };
TEST { $a->warn00() eq 'a' };
TEST { $b->warn00() eq 'a' };

# 21..28
TEST { 1 };
TEST { !defined $a->carp00() };
TEST { $b->carp00('c') eq 'c' };
TEST { $a->carp00() eq 'c' };
TEST { eval{$w=0;1}; eval{$a->carp00('d')}; $w==1 && length($@) };
TEST { eval{$w=0;1}; eval{$b->carp00('d')}; $w==1 && length($@) };
TEST { $a->carp00() eq 'c' };
TEST { $b->carp00() eq 'c' };

# 29..36
TEST { 1 };
TEST { !defined $a->myonce00() };
TEST { $b->myonce00('e') eq 'e' };
TEST { $a->myonce00() eq 'e' };
TEST { eval{$w=0;1}; eval{$a->myonce00('f')}; $w==0 && $@=~/^myonce/ };
TEST { eval{$w=0;1}; eval{$b->myonce00('f')}; $w==0 && $@=~/^myonce/ };
TEST { $a->myonce00() eq 'e' };
TEST { $b->myonce00() eq 'e' };

# 37..42
TEST { 1 };
TEST { !defined $a->ignore00() };
TEST { $b->ignore00('g') eq 'g' };
TEST { $a->ignore00() eq 'g' };
TEST { eval{$w=0;1}; eval{$a->ignore00('h')}; $w==0 && !length($@) };
TEST { eval{$w=0;1}; eval{$b->ignore00('h')}; $w==0 && !length($@) };
TEST { $a->ignore00() eq 'g' };
TEST { $b->ignore00() eq 'g' };

exit 0;

