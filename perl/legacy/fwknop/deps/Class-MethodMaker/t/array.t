# (X)Emacs mode: -*- cperl -*-

use strict;

=head1 Unit Test Package for Class::MethodMaker

This package tests the array type of Class::MethodMaker

=cut

use B::Deparse             0.59 qw( );
use Data::Dumper                qw( Dumper );
use Fcntl                  1.03 qw( :DEFAULT );
use File::Spec::Functions       qw( catfile );
use File::stat                  qw( stat );
use FindBin                1.42 qw( $Bin $Script );
use IO::File               1.08 qw( );
use POSIX                  1.03 qw( S_ISDIR S_ISREG );
use Test                   1.13 qw( ok plan skip );

use lib $Bin;
use test qw( evcheck );

BEGIN {
  # 1 for compilation test,
  plan tests  => 438,
       todo   => [],
}

# ----------------------------------------------------------------------------

=head2 Test 1: compilation

This test confirms that the test script and the modules it calls compiled
successfully.

=cut

package X;

use Class::MethodMaker
  [ array => [qw/ a b -static s /],
  ];

package main;

ok 1, 1, 'compilation';

# -------------------------------------

=head2 Tests 2--3: bless

=cut

my ($x, $y);
ok evcheck(sub { $x = bless {}, 'X'; }, 'bless ( 1)'), 1,        'bless ( 1)';
ok evcheck(sub { $y = bless {}, 'X'; }, 'bless ( 2)'), 1,        'bless ( 2)';

# -------------------------------------

=head2 Tests 4--28: simple non-static

=cut

{
  my $n;

  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static ( 1)'), 1,
                                                     'simple non-static ( 1)');
  ok ! $n;                                          # simple non-static ( 2)
  ok(evcheck(sub { $n = $x->b_isset; }, 'simple non-static ( 3)'), 1,
                                                     'simple non-static ( 3)');
  ok ! $n;                                          # simple non-static ( 4)
  ok(evcheck(sub { $x->a(4); }, 'simple non-static ( 5)'),
   1,                                                'simple non-static ( 5)');
  ok(evcheck(sub { ($n) = $x->a; }, 'simple non-static ( 6)'), 1,
                                                     'simple non-static ( 6)');
  ok $n, 4,                                          'simple non-static ( 7)';
  ok(evcheck(sub { ($n) = $x->a(7); }, 'simple non-static ( 8)'), 1,
                                                     'simple non-static ( 8)');
  ok $n, 7,                                          'simple non-static ( 9)';
  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static (10)'), 1,
                                                     'simple non-static (10)');
  ok $n;                                            # simple non-static (11)
  ok(evcheck(sub { $n = $x->b_isset; }, 'simple non-static (12)'), 1,
                                                     'simple non-static (12)');
  ok ! $n;                                          # simple non-static (13)

  ok(evcheck(sub { $n = $x->a(7); }, 'simple non-static (14)'), 1,
                                                     'simple non-static (14)');
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok ref($n), 'ARRAY',                               'simple non-static (15)';
  ok @$n, 1,                                         'simple non-static (16)';
  ok $n->[0], 7,                                     'simple non-static (17)';


  ok(evcheck(sub { $n = $x->a_reset; }, 'simple non-static (18)'), 1,
                                                     'simple non-static (18)');
  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static (19)'), 1,
                                                     'simple non-static (19)');
  ok ! $n;                                          # simple non-static (20)
  ok(evcheck(sub { $n = $x->a; }, 'simple non-static (21)'), 1,
                                                     'simple non-static (21)');
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok ref($n), 'ARRAY',                               'simple non-static (22)';
  ok @$n, 0,                                         'simple non-static (23)';

  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static (24)'), 1,
                                                     'simple non-static (24)');
  ok ! $n;                                          # simple non-static (25)
}

# -------------------------------------

=head2 Tests 29--59: simple static

=cut

{
  my ($m, $n);

  ok(evcheck(sub { $n = $x->s_isset; }, 'simple static ( 1)'), 1,
                                                         'simple static ( 1)');
  ok ! $n;                                              # simple static ( 2)
  ok(evcheck(sub { $n = $y->s_isset; }, 'simple static ( 3)'), 1,
                                                         'simple static ( 3)');
  ok ! $n;                                              # simple static ( 4)

  ok(evcheck(sub { $x->s(14, 17); }, 'simple static ( 5)'),
   1,                                                    'simple static ( 5)');

  ok(evcheck(sub { $n = $x->s_isset; }, 'simple static ( 6)'), 1,
                                                         'simple static ( 6)');
  ok $n;                                                # simple static ( 7)
  ok(evcheck(sub { $n = $y->s_isset; }, 'simple static ( 8)'), 1,
                                                         'simple static ( 8)');
  ok $n;                                                # simple static ( 9)

  ok(evcheck(sub { ($m, $n) = $x->s; }, 'simple static (10)'), 1,
                                                         'simple static (10)');
  ok $m, 14,                                             'simple static (11)';
  ok $n, 17,                                             'simple static (12)';
  ok(evcheck(sub { ($m, $n) = $y->s; }, 'simple static (13)'), 1,
                                                         'simple static (13)');
  ok $m, 14,                                             'simple static (14)';
  ok $n, 17,                                             'simple static (15)';

  ok(evcheck(sub { $n = $y->s; }, 'simple static (16)'), 1,
                                                         'simple static (16)');
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok ref($n), 'ARRAY',                                   'simple static (17)';
  ok @$n, 2,                                             'simple static (18)';
  ok $n->[0], 14,                                        'simple static (19)';
  ok $n->[1], 17,                                        'simple static (20)';


  ok(evcheck(sub { $n = $y->s_reset; }, 'simple static (21)'), 1,
                                                         'simple static (21)');
  ok(evcheck(sub { $n = $x->s_isset; }, 'simple static (22)'), 1,
                                                         'simple static (22)');
  ok ! $n;                                              # simple static (23)
  ok(evcheck(sub { $n = $y->s_isset; }, 'simple static (24)'), 1,
                                                         'simple static (24)');
  ok ! $n;                                              # simple static (25)

  ok(evcheck(sub { $n = $x->s; }, 'simple static (26)'), 1,
                                                         'simple static (26)');
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok ref($n), 'ARRAY',                                   'simple static (27)';
  ok @$n, 0,                                             'simple static (28)';
  ok(evcheck(sub { ($m, $n) = $y->s; }, 'simple static (29)'), 1,
                                                         'simple static (29)');
  ok $m, undef,                                          'simple static (30)';
  ok $n, undef,                                          'simple static (31)';
}

# -------------------------------------

=head2 Tests 60--80: typed

=cut

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([array =>
                                                 [{ -type => 'File::stat' },
                                                  qw( st ), ]])},
             'typed ( 1)'),
     1,                                                          'typed ( 1)');
  ok(evcheck(sub { $n = $x->st_isset; }, 'typed ( 2)'), 1,       'typed ( 2)');
  ok ! $n;                                                      # typed ( 3)
  ok(evcheck(sub { $x->st(4); }, 'typed ( 4)'), 0,               'typed ( 4)');
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  ok(evcheck(sub { ($n) = $x->st; }, 'typed ( 5)'), 1,           'typed ( 5)');
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  ok $n, undef,                                                  'typed ( 6)';
  ok(evcheck(sub { $n = $x->st_isset; }, 'typed ( 7)'), 1,       'typed ( 7)');
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  ok ! $n;                                                      # typed ( 8)
  ok(evcheck(sub { $x->st(undef); }, 'typed ( 9)'), 1,           'typed ( 9)');
  ok(evcheck(sub { $n = $x->st_isset; }, 'typed (10)'), 1,       'typed (10)');
  ok $n;                                                        # typed (11)
  ok(evcheck(sub { ($n) = $x->st; }, 'typed (12)'), 1,           'typed (12)');
  ok $n, undef,                                                  'typed (13)';

  my $stat1 = stat catfile($Bin,$Script);
  my $stat2 = stat $Bin;
  ok(evcheck(sub { $x->st($stat1, $stat2) }, 'typed (14)'),
     1,                                                          'typed (14)');

  ok(evcheck(sub { $n = $x->st; }, 'typed (15)'), 1,             'typed (15)');
    print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok ref($n), 'ARRAY',                                           'typed (16)';
  ok @$n, 2,                                                     'typed (17)';
  ok $n->[0], $stat1,                                            'typed (18)';
  ok $n->[1], $stat2,                                            'typed (19)';

  ok S_ISREG($n->[0]->mode), 1,                                  'typed (20)';
  ok S_ISDIR($n->[1]->mode), 1,                                  'typed (21)';
}

# -------------------------------------

=head2 Tests 81--124: index

=cut

{
  my ($n, @n);

  ok evcheck(sub { $x->a(11, 12, 13); }, 'index ( 1)'), 1,       'index ( 1)';
  ok evcheck(sub { $n = $x->a_index(1) }, 'index ( 2)'), 1,      'index ( 2)';
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok $n, 12,                                                     'index ( 3)';

  ok evcheck(sub { @n = $x->a_index(2, 0); }, 'index ( 4)'), 1,  'index ( 4)';
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok @n, 2,                                                      'index ( 5)';
  ok $n[0], 13,                                                  'index ( 6)';
  ok $n[1], 11,                                                  'index ( 7)';

  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok(evcheck(sub { $x->a_set(2, 31) }, 'index ( 8)'), 1,
                                                                 'index ( 8)');
  ok evcheck(sub { @n = $x->a_index(2); }, 'index ( 9)'), 1, 'index ( 9)';
  print STDERR Data::Dumper->Dump([\@n], [qw(@n)])
    if $ENV{TEST_DEBUG};
  ok @n, 1,                                                      'index (10)';
  ok $n[0], 31,                                                  'index (11)';

  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok(evcheck(sub { ($x->a_set(2, 23, 0, 21)) }, 'index (12)'), 1,
                                                                 'index (12)');
  ok evcheck(sub { @n = $x->a_index(0,1,2); }, 'index (13)'), 1, 'index (13)';
  print STDERR Data::Dumper->Dump([\@n], [qw(@n)])
    if $ENV{TEST_DEBUG};
  ok @n, 3,                                                      'index (14)';
  ok $n[0], 21,                                                  'index (15)';
  ok $n[1], 12,                                                  'index (16)';
  ok $n[2], 23,                                                  'index (17)';

  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok(evcheck(sub { @n = ($x->a_set(4, 42, 1, 45)) }, 'index (18)'), 1,
                                                                 'index (18)');
  if ( 0 ) {
    print STDERR Data::Dumper->Dump([\@n], [qw(@n)])
      if $ENV{TEST_DEBUG};
    ok @n, 2,                                                    'index (19)';
    ok $n[0], 42,                                                'index (20)';
    ok $n[1], 45,                                                'index (21)';
  } else {
    ok 1, 1, sprintf('index (%2d)', $_)
      for 19..21;
  }

  # check intermediate index not set
  ok(evcheck(sub { $n = $x->a_isset(3) }, 'index (22)'), 1, 'index (22)');
  ok ! $n;                                                      # index (23)

  ok evcheck(sub { @n = $x->a }, 'index (24)'), 1,               'index (24)';
  print STDERR Data::Dumper->Dump([\@n], [qw(@n)])
    if $ENV{TEST_DEBUG};
  ok @n, 5,                                                      'index (25)';
  ok $n[0], 21,                                                  'index (26)';
  ok $n[1], 45,                                                  'index (27)';
  ok $n[2], 23,                                                  'index (28)';
  ok $n[3], undef,                                               'index (29)';
  ok $n[4], 42,                                                  'index (30)';

  # check intermediate index still not set
  ok(evcheck(sub { $n = $x->a_isset(3) }, 'index (31)'), 1, 'index (31)');
  ok ! $n;                                                      # index (32)

  if ( $ENV{_CMM_TEST_AV} ) {
    # test auto-vivication
    ok evcheck(sub { @n = $x->a_index(3, 0); }, 'index (33)'), 1,'index (33)';
    print STDERR Data::Dumper->Dump([$n], [qw($n)])
      if $ENV{TEST_DEBUG};
    ok @n, 2,                                                    'index (34)';
    ok $n[0], undef,                                             'index (35)';
    ok $n[1], 21,                                                'index (36)';

    # check intermediate index not set (subr not used as lvalue)
    ok(evcheck(sub { $n = $x->a_isset(3) }, 'index (37)'), 1,    'index (37)');
    ok ! $n;                                                    # index (38)

    ok(evcheck(sub { @n = $x->a_index(3, 0) = (); }, 'index (39)'), 1,
                                                                 'index (39)');
    print STDERR Data::Dumper->Dump([$n], [qw($n)])
      if $ENV{TEST_DEBUG};
    ok @n, 2,                                                    'index (40)';
    ok $n[0], undef,                                             'index (41)';
    ok $n[1], undef,                                             'index (42)';

    # check intermediate index now (subr used as lvalue)
    ok(evcheck(sub { $n = $x->a_isset(3) }, 'index (43)'), 1,    'index (43)');
    ok $n;                                                      # index (44)
  } else {
    ok 1, 1, sprintf "index skip (%02d)", $_
      for 33..44;
  }
}

# -------------------------------------

=head2 Tests 125--148: count

=cut

{
  my ($n, @n);

  ok evcheck(sub { @n = $x->a(11, 12, 13); }, 'count ( 1)'), 1,  'count ( 1)';
  ok @n, 3,                                                      'count ( 2)';
  ok $n[0], 11,                                                  'count ( 3)';
  ok $n[1], 12,                                                  'count ( 4)';
  ok $n[2], 13,                                                  'count ( 5)';
  ok evcheck(sub { $n = $x->a_count; }, 'count ( 6)'), 1,        'count ( 6)';
  ok $n, 3,                                                      'count ( 7)';


  ok(evcheck(sub { @n = $x->a(14, 15, 16, 17); }, 'count ( 8)'),
   1,                                                            'count ( 8)');
  ok @n, 4,                                                      'count ( 9)';
  ok $n[0], 14,                                                  'count (10)';
  ok $n[1], 15,                                                  'count (11)';
  ok $n[2], 16,                                                  'count (12)';
  ok $n[3], 17,                                                  'count (13)';
  ok evcheck(sub { $n = $x->a_count; }, 'count (14)'), 1,        'count (14)';
  ok $n, 4,                                                      'count (15)';

  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok evcheck(sub { $x->a_set(8, 19); }, 'count (16)'), 1,        'count (16)';
  ok evcheck(sub { $n = $x->a_count; }, 'count (17)'), 1,        'count (17)';
  ok $n, 9,                                                      'count (18)';

  ok(evcheck(sub { @n = $x->a_index(7,8) }, 'count (19)'), 1,    'count (19)');
  ok @n, 2,                                                      'count (20)';
  ok $n[0], undef,                                               'count (21)';
  ok $n[1], 19,                                                  'count (22)';

  # check intermediate index still not set
  ok(evcheck(sub { $n = $x->a_isset(6) }, 'count (23)'), 1, 'count (23)');
  ok ! $n                                                       # count (24)
}

# -------------------------------------

=head2 Tests 149--243: default

=cut

{
  my ($n, @n);
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([array =>
                                                 [{ -default => 7,
                                                  },
                                                  qw( df1 ),
                                                 ],
                                               ]);
                 }, 'default ( 1)'), 1,                        'default ( 1)');
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok(evcheck(sub { $n = $x->df1_isset; }, 'default ( 2)'), 1,  'default ( 2)');
  ok $n;                                                      # default ( 3)
  ok(evcheck(sub { $n = $x->df1_count; }, 'default ( 4)'), 1,  'default ( 4)');
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  ok $n, undef,                                                'default ( 5)';

  ok(evcheck(sub { $n = $x->df1; },       'default ( 6)'), 1,  'default ( 6)');
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok ref($n), 'ARRAY',                                         'default ( 7)';
  ok @$n, 0,                                                   'default ( 8)';

  # test index (since it has a different implementation with defaults)
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  ok evcheck(sub { $n = $x->df1_index(1) }, 'default ( 9)'), 1,'default ( 9)';
  ok $n, 7,                                                    'default (10)';

  # check that item has been vivified
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  ok(evcheck(sub { $n = $x->df1_isset; }, 'default (11)'), 1,  'default (11)');
  ok $n;                                                      # default (12)
  ok(evcheck(sub { $n = $x->df1_isset(0); }, 'default (13)'),1,'default (13)');
  ok $n;                                                      # default (14)
  ok(evcheck(sub { $n = $x->df1_isset(1); }, 'default (15)'),1,'default (15)');
  ok $n;                                                      # default (16)
  ok evcheck(sub { $n = $x->df1_count }, 'default (17)'), 1,   'default (17)';
  ok $n, 2,                                                    'default (18)';

  # test reset (unset value)
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  ok evcheck(sub { $x->df1_reset(0) }, 'default (19)'), 1,     'default (19)';
  ok(evcheck(sub { $n = $x->df1_isset; }, 'default (20)'), 1,  'default (20)');
  ok $n;                                                      # default (21)
  ok(evcheck(sub { $n = $x->df1_isset(0); }, 'default (22)'),1,'default (22)');
  ok $n;                                                      # default (23)
  ok(evcheck(sub { $n = $x->df1_isset(1); }, 'default (24)'),1,'default (24)');
  ok $n;                                                      # default (25)
  ok evcheck(sub { $n = $x->df1_count }, 'default (26)'), 1,   'default (26)';
  ok $n, 2,                                                    'default (27)';

  # test reset (set value)
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  ok evcheck(sub { $x->df1_reset(1) }, 'default (28)'), 1,     'default (28)';
  ok(evcheck(sub { $n = $x->df1_isset; }, 'default (29)'), 1,  'default (29)');
  ok $n;                                                      # default (30)
  ok(evcheck(sub { $n = $x->df1_isset(0); }, 'default (31)'),1,'default (31)');
  ok $n;                                                      # default (32)
  ok(evcheck(sub { $n = $x->df1_isset(1); }, 'default (33)'),1,'default (33)');
  ok $n;                                                      # default (34)
  ok evcheck(sub { $n = $x->df1_count }, 'default (35)'), 1,   'default (35)';
  ok $n, 0,                                                    'default (36)';
  # check that x returns default for unset items
  ok evcheck(sub { $n = $x->df1_index(1) }, 'default (37)'), 1,'default (37)';
  ok $n, 7,                                                    'default (38)';
  # check that such items are now set
  ok(evcheck(sub { $n = $x->df1_isset(0); }, 'default (39)'),1,'default (39)');
  ok $n;                                                      # default (40)
  ok(evcheck(sub { $n = $x->df1_isset(1); }, 'default (41)'),1,'default (41)');
  ok $n;                                                      # default (42)
  ok evcheck(sub { $n = $x->df1_count }, 'default (43)'), 1,   'default (43)';
  ok $n, 2,                                                    'default (44)';
  # check this doesn't clobber undef items
  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok(evcheck(sub { $n = $x->df1_set(0, undef) }, 'default (45)'), 1,
                                                               'default (45)');
  ok $n, undef,                                                'default (46)';
  ok evcheck(sub { $n = $x->df1_index(0) }, 'default (47)'), 1,'default (47)';
  ok $n, undef,                                                'default (48)';
  ok(evcheck(sub { $n = $x->df1_isset(0); }, 'default (49)'),1,'default (49)');
  ok $n;                                                    # default (50)
  ok(evcheck(sub { $n = $x->df1_isset(1); }, 'default (51)'),1,'default (51)');
  ok $n;                                                      # default (52)
  ok evcheck(sub { $n = $x->df1_count }, 'default (53)'), 1,   'default (53)';
  ok $n, 2,                                                    'default (54)';


  ok evcheck(sub { $x->df1_reset(0) }, 'default (55)'), 1,     'default (55)';
  ok evcheck(sub { $x->df1_reset(1) }, 'default (56)'), 1,     'default (56)';

  # set i2 to value, test i2 & i0 & i1
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok evcheck(sub { $x->df1_set(2, 9) }, 'default (57)'), 1, 'default (57)';
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  ok(evcheck(sub { $n = $x->df1_isset; }, 'default (58)'), 1,  'default (58)');
  ok $n;                                                      # default (59)
  ok(evcheck(sub { $n = $x->df1_isset(0); }, 'default (60)'),1,'default (60)');
  ok $n;                                                      # default (61)
  ok(evcheck(sub { $n = $x->df1_isset(1); }, 'default (62)'),1,'default (62)');
  ok $n;                                                      # default (63)
  ok(evcheck(sub { $n = $x->df1_isset(2); }, 'default (64)'),1,'default (64)');
  ok $n;                                                      # default (65)
  ok evcheck(sub { $n = $x->df1_count }, 'default (66)'), 1,   'default (66)';
  ok $n, 3,                                                    'default (67)';
  ok evcheck(sub { $n = $x->df1_index(2) }, 'default (68)'), 1, 'default (68)';
  ok $n, 9,                                                    'default (69)';

  # test reset (aggregate)
  ok evcheck(sub { $x->df1_reset },    'default (70)'), 1,     'default (70)';
  ok(evcheck(sub { $n = $x->df1_isset; }, 'default (71)'), 1,  'default (71)');
  ok $n;                                                      # default (72)
  ok evcheck(sub { $n = $x->df1_count }, 'default (73)'), 1,   'default (73)';
  ok $n, undef,                                                'default (74)';
  ok(evcheck(sub { $n = $x->df1_isset(0); }, 'default (75)'),1,'default (75)');
  ok $n;                                                      # default (76)
  ok(evcheck(sub { $n = $x->df1_isset(1); }, 'default (77)'),1,'default (77)');
  ok $n;                                                      # default (78)
  ok(evcheck(sub { $n = $x->df1_isset(2); }, 'default (79)'),1,'default (79)');
  ok $n;                                                      # default (80)

  # set value to empty
  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok evcheck(sub { $x->df1_set(2, undef) },'default (81)'),1,'default (81)';
  ok(evcheck(sub { $n = $x->df1_isset; }, 'default (82)'), 1,  'default (82)');
  ok $n;                                                      # default (83)
  ok(evcheck(sub { $n = $x->df1_isset(0); }, 'default (84)'),1,'default (84)');
  ok $n;                                                      # default (85)
  ok(evcheck(sub { $n = $x->df1_isset(1); }, 'default (86)'),1,'default (86)');
  ok $n;                                                      # default (87)
  ok(evcheck(sub { $n = $x->df1_isset(2); }, 'default (88)'),1,'default (88)');
  ok $n;                                                      # default (89)
  ok evcheck(sub { $n = $x->df1_count }, 'default (90)'), 1,   'default (90)';
  ok $n, 3,                                                    'default (91)';
  ok evcheck(sub { $n = $x->df1_index(2) }, 'default (92)'), 1,'default (92)';
  ok $n, undef,                                                'default (93)';
  ok evcheck(sub { $n = $x->df1_index(1) }, 'default (94)'), 1,'default (94)';
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok $n, 7,                                                    'default (95)';


  ok evcheck(sub { @n = $x->df1 },         'default (96)'), 1, 'default (96)';
  ok @n, 3,                                                    'default (97)';
  ok $n[0], 7,                                                 'default (98)';
  ok $n[1], 7,                                                 'default (99)';
  ok $n[2], undef,                                            'default (100)';
}

# -------------------------------------

=head2 Tests 249--265: default_ctor

=cut

{
  package Y;
  my $count = 0;
  sub new {
    my $class = shift;
    my $i = shift;
    my $self = @_ ? $_[0] : ++$count;
    return bless \$self, $class;
  }

  sub value {
    return ${$_[0]};
  }

  sub reset {
    $count = 0;
  }
}

{
  my ($n, @n);
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([array =>
                                                 [{ -type => 'Y',
                                                    -default_ctor => 'new',
                                                  },
                                                  qw( df2 ),
                                                  { -type => 'Y',
                                                    -default_ctor =>
                                                      sub {
                                                        Y->new(undef, -3);
                                                      },
                                                  },
                                                  qw( df3 ),
                                                 ],
                                               ]);
                 }, 'default ( 1)'), 1,                   'default_ctor ( 1)');
  ok(evcheck(sub { $n = $x->df2_isset; }, 'default_ctor( 2)'), 1,
                                                          'default_ctor ( 2)');
  ok $n;                                                 # default_ctor ( 3)
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  ok(evcheck(sub { $n = $x->df2_index(1)->value; }, 'default_ctor( 4)'), 1,
                                                          'default_ctor ( 4)');
  ok $n, 1,                                               'default_ctor ( 5)';
  # This actually creates two Y instances; one explicitly, and one not implictly
  # by the _index method defaulting one (since it can't see the incoming)
  # XXX not anymore XXX
  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok(evcheck(sub { $x->df2_set(2, Y->new) }, 'default_ctor( 6)'), 1,
                                                          'default_ctor ( 6)');
  ok(evcheck(sub { $n = $x->df2_index(2)->value; }, 'default_ctor( 7)'), 1,
                                                          'default_ctor ( 7)');
  ok $n, 2,                                               'default_ctor ( 8)';
  ok(evcheck(sub { $x->df2_reset; },'default_ctor( 9)'), 1,
                                                          'default_ctor ( 9)');
  ok(evcheck(sub { $n = $x->df2_isset; }, 'default_ctor(10)'), 1,
                                                          'default_ctor (10)');
  ok $n;                                                 # default_ctor (11)
  ok(evcheck(sub { $n = $x->df2_index(2)->value; }, 'default_ctor(12)'), 1,
                                                          'default_ctor (12)');
  ok $n, 3,                                               'default_ctor (13)';
  ok(evcheck(sub { $n = $x->df3_isset; }, 'default_ctor(14)'), 1,
                                                          'default_ctor (14)');
  ok $n;                                                 # default_ctor (15)
  ok(evcheck(sub { $n = $x->df3_index(2)->value; }, 'default_ctor(16)'), 1,
                                                          'default_ctor (16)');
  ok $n, -3,                                              'default_ctor (17)';

  ok evcheck(sub { @n = $x->df2 }, 'default_ctor (18)'),1,'default_ctor (18)';
  ok @n, 3,                                               'default_ctor (19)';
  ok ref($n[2]), 'Y',                                     'default_ctor (20)';
  ok $n[2]->value, 3,                                     'default_ctor (21)';
  ok ref($n[0]), 'Y',                                     'default_ctor (22)';
  ok ref($n[1]), 'Y',                                     'default_ctor (23)';
}

# -------------------------------------

=head2 Tests 272--293: forward

=cut

{
  my ($n, @n);
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([array =>
                                                 [{ -type => 'File::stat',
                                                    -forward => [qw/ mode
                                                                     size /],
                                                  },
                                                  qw( st1 ),
                                                  # Keeping the second call
                                                  # here ensures that we check
                                                  # that mode, size are
                                                  # forwarded to st1
                                                  { -type => 'IO::Handle',
                                                    -forward => 'read', },
                                                  qw( st2 ),
                                                 ]])},
             'forward ( 1)'),
     1,                                                        'forward ( 1)');
  ok(evcheck(sub { $n = $x->st1_isset; }, 'forward ( 2)'), 1,  'forward ( 2)');
  ok ! $n;                                                    # forward ( 3)
  ok(evcheck(sub { $x->st1(4); }, 'forward ( 4)'), 0,          'forward ( 4)');
  ok(evcheck(sub { @n = $x->st1; }, 'forward ( 5)'), 1,        'forward ( 5)');
  ok @n, 0,                                                    'forward ( 6)';
  ok(evcheck(sub { $n = $x->st1_isset; }, 'forward ( 7)'), 1,  'forward ( 7)');
  ok ! $n;                                                    # forward ( 8)
  ok(evcheck(sub { $x->st1(undef); }, 'forward ( 9)'), 1,      'forward ( 9)');
  ok(evcheck(sub { $n = $x->st1_isset; }, 'forward (10)'), 1,  'forward (10)');
  ok $n;                                                      # forward (11)
  ok(evcheck(sub { @n = $x->st1; }, 'forward (12)'), 1,        'forward (12)');
  ok @n, 1,                                                    'forward (13)';
  ok $n[0], undef,                                             'forward (14)';
  ok(evcheck(sub { $x->st1(stat(catfile($Bin,$Script)),
                           stat(catfile($Bin))) }, 'forward (15)'),
     1,                                                        'forward (15)');
  print STDERR Data::Dumper->Dump([$x],[qw(x)])
    if $ENV{TEST_DEBUG};
  print STDERR B::Deparse->new('-p', '-sC')->coderef2text(\&X::mode), "\n"
    if $ENV{TEST_DEBUG};
  ok(evcheck(sub { @n = $x->mode; }, 'forward (16)'), 1,       'forward (16)');

  ok @n, 2,                                                    'forward (17)';
  ok S_ISREG($n[0]), 1,                                        'forward (18)';
  ok S_ISDIR($n[1]), 1,                                        'forward (19)';

  ok(evcheck(sub { $n = $x->size; }, 'forward (20)'), 1,       'forward (20)');
  ok @$n, 2,                                                   'forward (21)';
  {
    sysopen my $fh, catfile($Bin,$Script), O_RDONLY;
    local $/ = undef;
    my $text = <$fh>;
    close $fh;
    ok $n->[0], length($text),                                 'forward (22)';
  }
}

# -------------------------------------

=head2 Tests 294--296: forward_args

=cut

{
  my $n;
  # Instantiate st2 as IO::File, which is a subclass of IO::Handle.  This
  # should be fine
  ok(evcheck(sub { $x->st2(IO::File->new(catfile($Bin,$Script))) },
             'forward_args ( 1)'), 1,                     'forward_args ( 1)');
  ok(evcheck(sub { $x->read($n, 30); }, 'forward_args ( 2)'), 1,
                                                          'forward_args ( 2)');
  ok $n, '# (X)Emacs mode: -*- cperl -*-',                'forward_args ( 3)';
}



# -------------------------------------

=head2 Tests 297--349: manipulate

=cut

{
  my ($n, @n);

  Y::reset;

  ok evcheck(sub { $x->df2_reset; }, 'manipulate ( 1)'), 1, 'manipulate ( 1)';

  # _push
  ok evcheck(sub { $x->df2_push(Y->new, Y->new); }, 'manipulate ( 2)'), 1,
                                                            'manipulate ( 2)';
  ok evcheck(sub { @n = $x->df2; }, 'manipulate ( 3)'), 1,  'manipulate ( 3)';
  ok @n, 2,                                                 'manipulate ( 4)';
  ok $n[0]->value, 1,                                       'manipulate ( 5)';
  ok $n[1]->value, 2,                                       'manipulate ( 6)';
  # _push typecheck
  ok(evcheck(sub { $x->df2_push(+{}); }, 'manipulate ( 7)'),
     0,                                                     'manipulate ( 7)');

  # _unshift
  ok evcheck(sub { $x->df2_unshift(undef); },   'manipulate ( 8)'), 1,
                                                            'manipulate ( 8)';
  ok evcheck(sub { $x->df2_unshift(Y->new); },   'manipulate ( 9)'), 1,
                                                            'manipulate ( 9)';
  ok evcheck(sub { @n = $x->df2; }, 'manipulate (10)'), 1,  'manipulate (10)';
  ok @n, 4,                                                 'manipulate (11)';
  ok $n[0]->value, 3,                                       'manipulate (12)';
  ok $n[1], undef,                                          'manipulate (13)';
  ok $n[2]->value, 1,                                       'manipulate (14)';
  ok $n[3]->value, 2,                                       'manipulate (15)';
  # _unshift typecheck
  ok(evcheck(sub { $x->df2_unshift(+{}); }, 'manipulate (16)'),
     0,                                                     'manipulate (16)');

  # _pop
  ok evcheck(sub { $n = $x->df2_pop }, 'manipulate (17)'),1,'manipulate (17)';
  ok $n->value, 2,                                          'manipulate (18)';

  ok evcheck(sub {$n = $x->df2_pop(2)},'manipulate (19)'),1,'manipulate (19)';
  ok @$n, 2,                                                'manipulate (20)';
  ok $n->[0], undef,                                        'manipulate (21)';
  ok $n->[1]->value, 1,                                     'manipulate (22)';

  # _shift
  ok evcheck(sub { $x->df2_push(Y->new, Y->new); }, 'manipulate (23)'), 1,
                                                            'manipulate (23)';
  ok(evcheck(sub { $n = $x->df2_shift }, 'manipulate (24)'),
     1,                                                     'manipulate (24)');
  ok $n->value, 3,                                          'manipulate (25)';
  ok(evcheck(sub { @n = $x->df2_shift(2) }, 'manipulate (26)'),
     1,                                                     'manipulate (26)');
  ok @n, 2,                                                 'manipulate (27)';
  ok $n[0]->value, 4,                                       'manipulate (28)';
  ok $n[1]->value, 5,                                       'manipulate (29)';

  print STDERR Data::Dumper->Dump([$x->{df2}], [qw(df2)])
    if $ENV{TEST_DEBUG};
  # _splice
  ok(evcheck(sub { $x->df2_push(Y->new, Y->new, Y->new, Y->new); },
             'manipulate (29)'), 1,                         'manipulate (30)');
  print STDERR B::Deparse->new('-p','-sC')->coderef2text(\&X::df2_splice),"\n"
    if $ENV{TEST_DEBUG};
  print STDERR Data::Dumper->Dump([$x->{df2}], [qw(df2)])
    if $ENV{TEST_DEBUG};
  ok(evcheck(sub { $n = $x->df2_splice(1, 2) }, 'manipulate (31)'),
     1,                                                     'manipulate (31)');
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok @$n, 2,                                                'manipulate (32)';
  ok $n->[0]->value, 7,                                     'manipulate (33)';
  ok $n->[1]->value, 8,                                     'manipulate (34)';

  ok(evcheck(sub { @n = $x->df2_splice(0, 2, Y->new, Y->new, Y->new)},
             'manipulate (35)'), 1,                         'manipulate (35)');
  ok @n, 2,                                                 'manipulate (36)';
  ok $n[0]->value, 6,                                       'manipulate (37)';
  ok $n[1]->value, 9,                                       'manipulate (38)';
  ok(evcheck(sub { @n = $x->df2}, 'manipulate (39)'), 1,    'manipulate (39)');
  ok @n, 3,                                                 'manipulate (40)';
  ok $n[0]->value, 10,                                      'manipulate (41)';
  ok $n[1]->value, 11,                                      'manipulate (42)';
  ok $n[2]->value, 12,                                      'manipulate (43)';

  # splice with 1 argument (special case in code)
  ok(evcheck(sub { @n = $x->df2_splice(1) }, 'manipulate (44)'),
     1,                                                     'manipulate (44)');
  ok @n, 2,                                                 'manipulate (45)';
  ok $n[0]->value, 11,                                      'manipulate (46)';
  ok $n[1]->value, 12,                                      'manipulate (47)';

  # splice with 0 arguments (special case in code)
  ok(evcheck(sub { $x->df2_push(Y->new, Y->new); },
             'manipulate (48)'), 1,                         'manipulate (48)');
  ok(evcheck(sub { @n = $x->df2_splice }, 'manipulate (48)'),
     1,                                                     'manipulate (49)');
  ok @n, 3,                                                 'manipulate (50)';
  ok $n[0]->value, 10,                                      'manipulate (51)';
  ok $n[1]->value, 13,                                      'manipulate (52)';
  ok $n[2]->value, 14,                                      'manipulate (53)';
}

# -------------------------------------

=head2 Tests 350-392: tie

=cut

{
  # @z is an audit trail
  my @z;
  package Z;
  use base qw( Tie::StdArray );
  sub TIEARRAY { push @z, [ 'TIEARRAY'      ]; $_[0]->SUPER::TIEARRAY         }
  sub FETCH    { push @z, [ FETCH => $_[1]  ]; $_[0]->SUPER::FETCH($_[1])     }
  sub PUSH     { push @z, [ PUSH  => $_[1]  ]; $_[0]->SUPER::PUSH(@_[1..$#_]) }
  sub STORE    { push @z, [ STORE => @_[1,2]]; $_[0]->SUPER::STORE(@_[1,2])   }
  sub DESTROY  { push @z, [ 'DESTROY'       ]; $_[0]->SUPER::DESTROY          }
  package main;

  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([array =>
                                                 [{ -type      => 'File::stat',
                                                    -tie_class => 'Z',
                                                    -forward   => [qw/ mode
                                                                       size /],
                                                  },
                                                  qw( tie1 ),
                                                 ]])},
             'tie ( 1)'),
     1,                                                            'tie ( 1)');

  bless ((my $x = {}), 'X');

  ok @z, 0,                                                        'tie ( 2)';

  my $stat1 = stat catfile($Bin,$Script);
  my $stat2 = stat $Bin;
  $x->tie1_push($stat1);

  ok @z, 2,                                                        'tie ( 3)';
  ok $z[0][0], 'TIEARRAY',                                         'tie ( 4)';
  ok $z[1][0], 'PUSH'    ,                                         'tie ( 5)';
  ok $z[1][1], $stat1    ,                                         'tie ( 6)';

  my $y;
  ok evcheck(sub { $y = $x->tie1_index(0) }, 'tie ( 7)'), 1,       'tie ( 7)';
  ok $y, $stat1,                                                   'tie ( 8)';
  ok @z, 3,                                                        'tie ( 9)';
  ok $z[2][0], 'FETCH',                                            'tie (10)';
  ok $z[2][1], 0,                                                  'tie (11)';

  ok evcheck(sub { $y = $x->tie1_index(2) }, 'tie (12)'), 1,       'tie (12)';
  ok $y, undef,                                                    'tie (13)';
  ok @z, 4,                                                        'tie (14)';
  ok $z[3][0], 'FETCH',                                            'tie (15)';
  ok $z[3][1], 2,                                                  'tie (16)';

  ok evcheck(sub { $x->tie1_set(2, $stat2) },    'tie (17)'), 1,   'tie (17)';
  ok @z, 5,                                                        'tie (18)';
  ok $z[4][0], 'STORE',                                            'tie (19)';
  ok $z[4][1], 2,                                                  'tie (20)';
  ok $z[4][2], $stat2,                                             'tie (21)';

  ok evcheck(sub { $y = $x->tie1 }, 'tie (22)'), 1,                'tie (22)';
  ok ref $y, 'ARRAY',                                              'tie (23)';
  ok @$y, 3,                                                       'tie (24)';
  ok $y->[0], $stat1,                                              'tie (25)';
  ok $y->[1], undef,                                               'tie (26)';
  ok $y->[2], $stat2,                                              'tie (27)';
  ok @z, 8,                                                        'tie (28)';
  ok $z[$_][0], 'FETCH',                          sprintf 'tie (%02d)', $_+24
    for 5..7;
  ok $z[$_][1], $_-5,                             sprintf 'tie (%02d)', $_+27
    for 5..7;

  ok evcheck(sub { $x->tie1_reset }, 'tie (35)'), 1,               'tie (35)';
  ok @z, 9,                                                        'tie (36)';
  ok $z[8][0], 'DESTROY',                                          'tie (37)';

  ok evcheck(sub { $y = $x->tie1_count }, 'tie (38)'), 1,          'tie (38)';
  ok $y, undef,                                                    'tie (39)';
  ok @z, 9,                                                        'tie (40)';

  ok evcheck(sub { $y = $x->tie1_index(2) }, 'tie (41)'), 1,       'tie (41)';
  ok $y, undef,                                                    'tie (42)';
  ok @z, 9,                                                        'tie (43)';

  # Beware that indexing items off the end of @z above will auto-vivify the
  # corresponding entries, so if you see empty members of @z, that's possibly
  # the cause
  print Dumper \@z, $x
    if $ENV{TEST_DEBUG};
}

# -------------------------------------

=head2 Tests 393-396 : void set

Check that calling a(), with no arguments, doesn't instantiate a new instance
(in all contexts).

=cut

{
  my $x = bless {}, 'X';
  ok ! $x->a_isset;
  $x->a();
  ok ! $x->a_isset;
  my @a = $x->a();
  ok ! $x->a_isset;
  my $a = $x->a();
  ok ! $x->a_isset;
}

# -------------------------------------

=head2 Tests 397--418: _clear

=cut

{
  my ($n, @n);

  ok evcheck(sub { $n = $x->a_reset; }, '_clear ( 1)'), 1,      '_clear ( 1)';
  ok evcheck(sub { $n = $x->a_isset; }, '_clear ( 2)'), 1,      '_clear ( 2)';
  ok ! $n;                                                     # _clear ( 3)


  ok evcheck(sub { $x->a(4); }, '_clear ( 4)'), 1,              '_clear ( 4)';
  ok evcheck(sub { ($n) = $x->a; }, '_clear ( 5)'), 1,          '_clear ( 5)';
  ok $n, 4,                                                     '_clear ( 6)';

  ok evcheck(sub { $x->a_clear; }, 'clear ( 7)'), 1,            '_clear ( 7)';
  ok evcheck(sub { $n = $x->a_isset; }, '_clear ( 8)'), 1,      '_clear ( 8)';
  ok $n;                                                       # _clear ( 9)
  ok evcheck(sub { (@n) = $x->a; },        '_clear (10)'), 1,   '_clear (10)';
  ok @n, 0,                                                     '_clear (11)';

  print STDERR Data::Dumper->Dump([\@n], [qw(@n)])
    if $ENV{TEST_DEBUG};

  ok evcheck(sub { (@n) = $x->a(7,8,9); }, '_clear (12)'), 1,   '_clear (12)';
  ok @n, 3,                                                     '_clear (13)';

  ok evcheck(sub { $x->a_clear; }, 'clear (14)'), 1,            '_clear (14)';
  ok evcheck(sub { $n = $x->a_isset; }, '_clear (15)'), 1,      '_clear (15)';
  ok $n;                                                       # _clear (16)
  ok evcheck(sub { (@n) = $x->a; },        '_clear (17)'), 1,   '_clear (17)';
  ok @n, 0,                                                     '_clear (18)';

  my $xx = \1;
  ok evcheck(sub { $x->a($xx); }, '_clear (19)'), 1,            '_clear (19)';
  ok evcheck(sub { @n = $x->a; }, '_clear (20)'), 1,            '_clear (20)';
  ok @n, 1,                                                     '_clear (21)';
  ok $n[0], $xx,                                                '_clear (22)';
}

# -------------------------------------

=head2 Tests 419--425: non-init ctor

This is to test that the default ctor or default is not assigned if a value is
supplied.  This would particularly be a problem with v1 compatibility use where
a value is explcitly supplied to prevent 'new' being called because there is
no 'new' (if the ctor is called anyway, the program barfs).

=cut

{
  my (@n, $n);
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([array =>
                                                 [{ -type => 'Y',
                                                    -default_ctor => 'newx',
                                                  },
                                                  qw( nic ),
                                                 ],
                                               ]);
                 }, 'default ( 1)'), 1,                  'non-init ctor ( 1)');
  ok(evcheck(sub { $n = $x->nic_isset; }, 'non-init ctor( 2)'), 1,
                                                         'non-init ctor ( 2)');
  ok $n;                                                # non-init ctor ( 3)
  ok(evcheck(sub { $n = $x->nic_index(0); }, 'non-init ctor( 4)'), 0,
                                                         'non-init ctor ( 4)');
  ok(evcheck(sub { $x->nic(Y->new); }, 'non-init ctor( 5)'), 1,
                                                         'non-init ctor ( 5)');
  ok(evcheck(sub { @n = $x->nic; }, 'non-init ctor( 6)'), 1,
                                                         'non-init ctor ( 6)');
  ok ref $n[0], 'Y',                                     'non-init ctor ( 7)';
}

# -------------------------------------

=head2 Tests 426--438: default_ctor (arg)

=cut

{
  package S;
  my $count = 0;
  sub new {
    my ($class, $arg) = @_;

    die sprintf "Expected an X, got a '%s'\n", defined($arg) ? ref $arg : '*undef*'
      unless UNIVERSAL::isa($arg, 'X');
    my ($self) = $arg->a;
    return bless \$self, $class;
  }

  sub value {
    return ${$_[0]};
  }
}

{
  my ($n, @n);
  $x->a(3);
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([array =>
                                                 [{ -type => 'S',
                                                    -default_ctor => 'new',
                                                  },
                                                  qw( dfx ),
                                                 ],
                                               ]);
                 }, 'default ( 1)'), 1,             'default_ctor (arg) ( 1)');
  ok(evcheck(sub { $n = $x->dfx_isset; }, 'default_ctor (arg)( 2)'), 1,
                                                    'default_ctor (arg) ( 2)');
  ok $n;                                           # default_ctor (arg) ( 3)
  ok(evcheck(sub { $n = $x->dfx_index(1)->value; }, 'default_ctor (arg)( 4)'), 1,
                                                    'default_ctor (arg) ( 4)');
  ok $n, 3,                                         'default_ctor (arg) ( 5)';
  print STDERR Data::Dumper->Dump([$x], [qw($x)])
    if $ENV{TEST_DEBUG};
  # This actually creates two Y instances; one explicitly, and one not implictly
  # by the _index method defaulting one (since it can't see the incoming)
  # XXX not anymore XXX
  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  my $xx = bless {}, "X"; $xx->a(2);
  ok(evcheck(sub { $x->dfx_set(2, S->new($xx)) }, 'default_ctor (arg)( 6)'), 1,
                                                    'default_ctor (arg) ( 6)');
  ok(evcheck(sub { $n = $x->dfx_index(2)->value; }, 'default_ctor (arg)( 7)'), 1,
                                                    'default_ctor (arg) ( 7)');
  ok $n, 2,                                         'default_ctor (arg) ( 8)';
  ok(evcheck(sub { $x->dfx_reset; },'default_ctor (arg)( 9)'), 1,
                                                    'default_ctor (arg) ( 9)');
  ok(evcheck(sub { $n = $x->dfx_isset; }, 'default_ctor (arg)(10)'), 1,
                                                    'default_ctor (arg) (10)');
  ok $n;                                           # default_ctor (arg) (11)
  ok(evcheck(sub { $n = $x->dfx_index(2)->value; }, 'default_ctor (arg)(12)'), 1,
                                                    'default_ctor (arg) (12)');
  ok $n, 3,                                         'default_ctor (arg) (13)';
}

# -------------------------------------

# _get _set
# _clear

# _isset(n,m,l)
# _reset(n,m,l)

# _setref
# _grep
# _map
# _for
# _areset

# ----------------------------------------------------------------------------
