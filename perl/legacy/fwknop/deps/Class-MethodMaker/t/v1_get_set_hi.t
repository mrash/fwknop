#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

# Tests for interaction of get_set with new_hash_init

package Person;

use Class::MethodMaker
  new_hash_init =>      'new' ,
  get_set       => [ -java   => 'Status',
                     -eiffel => 'size', 'name', ]
  ;

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $p = Person->new(name   =>'Homer',
                    size   =>'54', 
                    Status =>'Comical Moron');

TEST { 1 };
TEST { $p->name eq 'Homer'          };
TEST { $p->size == 54               };
TEST { $p->getStatus eq 'Comical Moron' };

exit 0;
