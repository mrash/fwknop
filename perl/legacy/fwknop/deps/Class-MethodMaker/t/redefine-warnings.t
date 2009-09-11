# (X)Emacs mode: -*- cperl -*-

use strict;

=head1 Unit Test Package for Class::MethodMaker

This package tests the basic utility of Class::MethodMaker

=cut

use FindBin 1.42 qw( $Bin );
use Test 1.13 qw( ok plan skip );

use lib $Bin;
use test qw( DATA_DIR
             evcheck save_output restore_output );

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

ok 1, 1, 'compilation';

# -------------------------------------

=head2 Test 2: no warnings generated

This tests for a bug in 2.00 where warnings are generated complaining of
'prototype mismatch' and 'INTEGER redefined' when using Class::MethodMaker
with certain other modules.  Currently IPC::Run is tested, which is
unfortunate, since it is non-core.  If someone can suggest a core module that
displays this issue with 2.00, that wouldd be great.

=cut

{
  save_output('stderr', *STDERR{IO});
  eval {
    require IPC::Run;
  };
  my $run_failed = $@;
  defined $run_failed && $run_failed =~ s/\(.*$//
    unless defined $ENV{TEST_DEBUG} and $ENV{TEST_DEBUG} > 1;
  eval {
    require Class::MethodMaker;
  };
  my $err = restore_output('stderr');
  skip $run_failed, $err, '', "No warnings generated\n";
}

# ----------------------------------------------------------------------------
