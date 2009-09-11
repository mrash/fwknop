#!/usr/local/bin/perl

package myArray;
use Tie::Array ;

@ISA=qw/Tie::StdArray/ ;

use vars qw/$log/ ;

$log = 'log: ';

sub TIEARRAY {
  my $class = shift;
  my $p = shift || '';
  #print "log $p ($log))\n";
  $log .= "tie $p,";
  return bless [], $class ;
}

sub STORE { my ($self, $idx, $value) = @_ ;
            #print "storing $idx, $value ...\n";
            $log .=  "store $idx,";
            $self->[$idx]=$value;
            return $value;}

package myObj ;
use ExtUtils::testlib;

use Class::MethodMaker
  get_set => [qw/a b c/]  ;

sub new
  {
    my $class = shift;

    bless { arg=> shift }, $class;
  }

sub all { my $self = shift; return join (' ', values %{$self}) ;}

package X ;
use ExtUtils::testlib;

use Class::MethodMaker
  object_tie_list =>
  [
   {
    slot => 'a',
    tie_array => ['myArray', "a"],
    class => ['myObj', 'a_obj']
   },
   {
    slot =>['b','c'],
    tie_array => ['myArray', "bc"],
    class => ['myObj', 'b_obj']
   }
  ],
  new => 'new';

package main;
use lib qw ( ./t );
use test_v1;

use ExtUtils::testlib;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

use Data::Dumper ;
my $o = new X;

TEST { 1 };
# create a list of 2 object with default constructor arguments
TEST {$o->a(1,2)} ;

if ( $ENV{TEST_DEBUG} ) {
  my @a = $o->a ;
  print Dumper \@a;
}

TEST {$o->a->[0]->all eq 'a_obj' };
TEST {$o->a->[1]->all eq 'a_obj' };

# verifie that tied array is used
TEST {$myArray::log eq 'log: tie a,store 0,store 1,'} ;

# create 2 object using constructor arguments
TEST {$o->b(['b1_obj'],['b2_obj'])} ;

if ( $ENV{TEST_DEBUG} ) {
  my @b = $o->b ;
  print Dumper \@b;
}

TEST {$o->b->[0]->all eq 'b1_obj' };
TEST {$o->b->[1]->all eq 'b2_obj' };
# verifie that tied array is used
TEST {$myArray::log eq 'log: tie a,store 0,store 1,tie bc,store 0,store 1,'};

# create 2 object and assign them
my @objs = (myObj->new('c1_obj'), myObj->new('c2_obj'));
TEST {$o->c(@objs)} ;
TEST {$o->c->[0]->all eq 'c1_obj' };
TEST {$o->c->[1]->all eq 'c2_obj' };

exit 0;

