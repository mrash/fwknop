# (X)Emacs mode: -*- cperl -*-

use strict;

=head1 Unit Test Package for Class::MethodMaker

This package tests the basic compilation and working of Class::MethodMaker

=cut

use Data::Dumper        qw( );
use FindBin        1.42 qw( $Bin );
use Test           1.13 qw( ok plan );

use lib $Bin;
use test qw( DATA_DIR
             evcheck );

BEGIN {
  # 1 for compilation test,
  plan tests  => 2,
       todo   => [],
}

# ----------------------------------------------------------------------------

=head2 Test 1: compilation

This test confirms that the test script and the modules it calls compiled
successfully.

=cut

use Class::MethodMaker;

ok 1, 1, 'compilation';

# -------------------------------------

=head2 Test 2: scalar

=cut

package bob;

use Class::MethodMaker
  [ scalar =>[qw/ foo /] ];

package main;

my $bob = bless {}, 'bob';
print Data::Dumper->Dump([ $bob ], [qw( bob )])
  if $ENV{TEST_DEBUG};
$bob->foo("x");
print Data::Dumper->Dump([ $bob ], [qw( bob )])
  if $ENV{TEST_DEBUG};
ok $bob->foo, "x",                                              'scalar ( 1)';

# ----------------------------------------------------------------------------
