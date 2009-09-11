# (X)Emacs mode: -*- cperl -*-

use strict;

=head1 Unit Test Package for Class::MethodMaker

This package tests the ability of Class::MethodMaker to insert methods into a
class other than the "Calling" class.

=cut

use Data::Dumper                qw( Dumper );
use Fatal                  1.02 qw( sysopen close );
use Fcntl                  1.03 qw( :DEFAULT );
use File::stat                  qw( stat );
use FindBin                1.42 qw( $Bin $Script );
use IO::File               1.08 qw( );
use POSIX                  1.03 qw( S_ISREG );
use Test                   1.13 qw( ok plan );

use lib $Bin;
use test qw( DATA_DIR
             evcheck restore_output save_output );

BEGIN {
  # 1 for compilation test,
  plan tests  => 22,
       todo   => [],
}

# ----------------------------------------------------------------------------

=head2 Test 1: compilation

This test confirms that the test script and the modules it calls compiled
successfully.

=cut

use Class::MethodMaker
  [ -target_class => 'X',
    scalar        => [qw/ a /],
    -target_class => 'Y',
    scalar        => [qw/ b /],
  ];

ok 1, 1, 'compilation';

# -------------------------------------

=head2 Test 2: bless

=cut

my ($x, $y);
ok evcheck(sub { $x = bless {}, 'X'; $y = bless {}, 'Y'; },
           'bless ( 1)'), 1,                                     'bless ( 1)';

goto "TEST_$ENV{START_TEST}"
  if $ENV{START_TEST};

# -------------------------------------

=head2 Tests 3--22: simple non-static

=cut

{
  my $n;

  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static ( 1)'), 1,
                                                     'simple non-static ( 1)');
  ok ! $n;                                          # simple non-static ( 2)
  ok(evcheck(sub { $n = $x->b_isset; }, 'simple non-static ( 3)'), 0,
                                                     'simple non-static ( 3)');
  ok(evcheck(sub { $n = $y->b_isset; }, 'simple non-static ( 4)'), 1,
                                                     'simple non-static ( 4)');

  ok(evcheck(sub { $x->a(4); }, 'simple non-static ( 5)'),
   1,                                                'simple non-static ( 5)');
  ok(evcheck(sub { $n = $x->a; }, 'simple non-static ( 6)'), 1,
                                                     'simple non-static ( 6)');
  ok $n, 4,                                          'simple non-static ( 7)';
  ok(evcheck(sub { $n = $x->a(7); }, 'simple non-static ( 8)'), 1,
                                                     'simple non-static ( 8)');
  ok $n, 7,                                          'simple non-static ( 9)';
  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static (10)'), 1,
                                                     'simple non-static (10)');
  ok $n;                                            # simple non-static (11)
  ok(evcheck(sub { $n = $y->b_isset; }, 'simple non-static (12)'), 1,
                                                     'simple non-static (12)');
  ok ! $n;                                          # simple non-static (13)
  ok(evcheck(sub { $n = $x->a_reset; }, 'simple non-static (14)'), 1,
                                                     'simple non-static (14)');
  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static (15)'), 1,
                                                     'simple non-static (15)');
  ok ! $n;                                          # simple non-static (16)
  ok(evcheck(sub { $n = $x->a; }, 'simple non-static (17)'), 1,
                                                     'simple non-static (17)');
  ok $n, undef,                                      'simple non-static (18)';
  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static (19)'), 1,
                                                     'simple non-static (19)');
  ok ! $n;                                          # simple non-static (20)
}

# -------------------------------------
