#!/usr/local/bin/perl

package myHash;
use Tie::Hash ;

@ISA=qw/Tie::StdHash/ ;

use vars qw/$log/ ;

$log = 'log: ';

sub TIEHASH {
  my $class = shift;
  my $p = shift || '';
  #print "log $p ($log))\n";
  $log .= "tie $p,";
  return bless {}, $class ;
}

sub STORE { my ($self, $idx, $value) = @_ ;
            #print "storing $idx, $value ...\n";
            $log .=  "store $idx,";
            $self->{$idx}=$value;
            return $value;}

package myObj ;
use ExtUtils::testlib;

use Class::MethodMaker
  get_set => [qw/a b c/]  ;

sub new
  {
    my $class = shift;
    bless { @_ }, $class;
  }

sub all { my $self = shift; return join (' ', values %{$self}) ;}

package X ;
use ExtUtils::testlib;

use Class::MethodMaker
  object_tie_hash =>
  [
   {
    slot => 'a',
    tie_hash => ['myHash', "log a"],
    class => ['myObj', 'a' => 'foo']
   },
   {
    slot =>['b','c'],
    tie_hash => ['myHash', "log bc"],
    class => ['myObj', 'b' => 'bar']
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
# create a hash of 2 object with default constructor arguments
TEST {$o->a(foo=> [], bar => [])} ;

#print Dumper $o ;
TEST {$o->a->{foo}->a eq 'foo'} ;
TEST {$o->a->{bar}->a eq 'foo'} ;

TEST {$o->a(foo2=> [a=> 'toto'])} ;

#print Dumper $o ;
TEST {$o->a->{foo2}->a eq 'toto'} ;

TEST {$o->b(foo2=> [a=> 'toto'])} ;
#print Dumper $o ;
TEST {$o->b->{foo2}->a eq 'toto'} ;


exit 0 ;
