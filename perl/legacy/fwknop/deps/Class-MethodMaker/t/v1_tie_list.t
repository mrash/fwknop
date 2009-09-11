#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package myArray;
use Tie::Array ;

@ISA=qw/Tie::StdArray/ ;

use vars qw/$prefix/ ;

$prefix = '';

sub TIEARRAY {
  my $class = shift;
  my $p = shift || '';
  #print "prefix $p ($prefix))\n";
  $prefix .= $p;
  return bless [], $class ;
}

sub FETCH { my ($self, $idx) = @_ ;
            #print "fetching $idx...\n";
            return $prefix.$self->[$idx];}

sub STORE { my ($self, $idx, $value) = @_ ;
            #print "storing $idx, $value ...\n";
            $self->[$idx]=$value;
            return $value;}

package X ;
use ExtUtils::testlib;

use Class::MethodMaker
  tie_list =>
  [
   a => ['myArray', "my "],
   ['b','c'] => ['myArray']
  ],
  new => 'new';

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

use ExtUtils::testlib;

use Data::Dumper ;
my $o = new X;

TEST { 1 };
TEST {$o->a(qw/0 1 2/)} ;
TEST {$o->b(qw/1 2 3 4/)} ;
TEST {$o->c(qw/a s d f/)} ;

my @r = $o->a ;

#print Dumper $o ;

TEST { $r[1] eq "my 1" };

TEST {$o->b_shift == 1}; # SHIFT not overloaded in myArray
TEST {$o->c_count == 4};

exit 0;

