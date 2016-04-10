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
  plan tests  => 439,
       todo   => [],
}

# ----------------------------------------------------------------------------

=head2 Test 1: compilation

This test confirms that the test script and the modules it calls compiled
successfully.

=cut

package X;

use Class::MethodMaker
  [ hash => [qw/ a b -static s /],
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

=head2 Tests 4--29: simple non-static

=cut

{
  my $n;

  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static ( 1)'), 1,
                                                     'simple non-static ( 1)');
  ok ! $n;                                          # simple non-static ( 2)
  ok(evcheck(sub { $n = $x->b_isset; }, 'simple non-static ( 3)'), 1,
                                                     'simple non-static ( 3)');
  ok ! $n;                                          # simple non-static ( 4)
  ok(evcheck(sub { $x->a(a => 4); }, 'simple non-static ( 5)'),
   1,                                                'simple non-static ( 5)');
  ok(evcheck(sub { ($n) = $x->a; }, 'simple non-static ( 6)'), 1,
                                                     'simple non-static ( 6)');
  ok $n, 'a',                                        'simple non-static ( 7)';
  ok(evcheck(sub { ($n) = $x->a(a => 7); }, 'simple non-static ( 8)'), 1,
                                                     'simple non-static ( 8)');
  ok $n, 'a',                                        'simple non-static ( 9)';
  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static (10)'), 1,
                                                     'simple non-static (10)');
  ok $n;                                            # simple non-static (11)
  ok(evcheck(sub { $n = $x->b_isset; }, 'simple non-static (12)'), 1,
                                                     'simple non-static (12)');
  ok ! $n;                                          # simple non-static (13)

  ok(evcheck(sub { $n = $x->a(b => 7); }, 'simple non-static (14)'), 1,
                                                     'simple non-static (14)');
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok ref($n), 'HASH',                                'simple non-static (15)';
  ok keys %$n, 1,                                    'simple non-static (16)';
  ok $n->{b}, 7,                                     'simple non-static (17)';

  ok(evcheck(sub { $n = $x->a_reset; }, 'simple non-static (18)'), 1,
                                                     'simple non-static (18)');
  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static (19)'), 1,
                                                     'simple non-static (19)');
  ok ! $n;                                          # simple non-static (20)
  ok(evcheck(sub { $n = $x->a; }, 'simple non-static (21)'), 1,
                                                     'simple non-static (21)');
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok ref($n), 'HASH',                                'simple non-static (22)';
  ok keys %$n, 0,                                    'simple non-static (23)';

  ok(evcheck(sub { $n = $x->a_isset; }, 'simple non-static (24)'), 1,
                                                     'simple non-static (24)');
  ok ! $n;                                          # simple non-static (25)
  # Fail this due to uneven number of arguments
  ok(evcheck(sub { $x->a(4); }, 'simple non-static ( 5)'),
     0,                                              'simple non-static (26)');
}

# -------------------------------------

=head2 Tests 30--60: simple static

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
  ok ref($n), 'HASH',                                    'simple static (17)';
  ok keys %$n, 1,                                        'simple static (18)';
  ok exists $n->{14};
  ok $n->{14}, 17,                                       'simple static (20)';


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
  ok ref($n), 'HASH',                                    'simple static (27)';
  ok keys %$n, 0,                                        'simple static (28)';
  ok(evcheck(sub { ($m, $n) = $y->s; }, 'simple static (29)'), 1,
                                                         'simple static (29)');
  ok $m, undef,                                          'simple static (30)';
  ok $n, undef,                                          'simple static (31)';
}

# -------------------------------------

=head2 Tests 61--81: typed

=cut

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([hash =>
                                                 [{ -type => 'File::stat' },
                                                  qw( st ), ]])},
             'typed ( 1)'),
     1,                                                          'typed ( 1)');
  ok(evcheck(sub { $n = $x->st_isset; }, 'typed ( 2)'), 1,       'typed ( 2)');
  ok ! $n;                                                      # typed ( 3)
  ok(evcheck(sub { $x->st(a => 4); }, 'typed ( 4)'), 0,          'typed ( 4)');
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
  ok(evcheck(sub { $x->st(bin => undef); }, 'typed ( 9)'), 1,    'typed ( 9)');
  ok(evcheck(sub { $n = $x->st_isset; }, 'typed (10)'), 1,       'typed (10)');
  ok $n;                                                        # typed (11)
  ok(evcheck(sub { (undef, $n) = $x->st; }, 'typed (12)'), 1,    'typed (12)');
  ok $n, undef,                                                  'typed (13)';

  my $stat1 = stat catfile($Bin,$Script);
  my $stat2 = stat $Bin;
  ok(evcheck(sub { $x->st(script => $stat1, bin => $stat2) }, 'typed (14)'),
     1,                                                          'typed (14)');

  ok(evcheck(sub { $n = $x->st; }, 'typed (15)'), 1,             'typed (15)');
    print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok ref($n), 'HASH',                                            'typed (16)';
  ok keys %$n, 2,                                                'typed (17)';
  ok $n->{script}, $stat1,                                       'typed (18)';
  ok $n->{bin}, $stat2,                                          'typed (19)';

  ok S_ISREG($n->{script}->mode), 1,                             'typed (20)';
  ok S_ISDIR($n->{bin}->mode), 1,                                'typed (21)';
}

# -------------------------------------

=head2 Tests 82--125: index

=cut

{
  my ($n, @n, %n);

  ok evcheck(sub { $x->a(a=>11,b=>12,c=>13); }, 'index ( 1)'), 1,'index ( 1)';
  ok evcheck(sub { $n = $x->a_index('b') }, 'index ( 2)'), 1,    'index ( 2)';
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok $n, 12,                                                     'index ( 3)';

  ok evcheck(sub { @n = $x->a_index(qw(c a)); }, 'index ( 4)'),1,'index ( 4)';
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok @n, 2,                                                      'index ( 5)';
  ok $n[0], 13,                                                  'index ( 6)';
  ok $n[1], 11,                                                  'index ( 7)';

  # test lvalue of index
  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok(evcheck(sub { $x->a_set(2, 31) }, 'index ( 8)'), 1,
                                                                 'index ( 8)');
  ok evcheck(sub { @n = $x->a_index(2); }, 'index ( 9)'), 1, 'index ( 9)';
  print STDERR Data::Dumper->Dump([\@n], [qw(@n)])
    if $ENV{TEST_DEBUG};
  ok @n, 1,                                                      'index (10)';
  ok $n[0], 31,                                                  'index (11)';

  # test index with multiple indices, also as lvalue
  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok(evcheck(sub { ($x->a_set(2, 23, 0, 21)) }, 'index (12)'), 1,
                                                                 'index (12)');
  ok evcheck(sub { @n = $x->a_index(0,1,2); }, 'index (13)'), 1, 'index (13)';
  print STDERR Data::Dumper->Dump([\@n], [qw(@n)])
    if $ENV{TEST_DEBUG};
  ok @n, 3,                                                      'index (14)';
  ok $n[0], 21,                                                  'index (15)';
  ok $n[1], undef,                                               'index (16)';
  ok $n[2], 23,                                                  'index (17)';

  # test lvalue with return value, with previously unseen index
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
    ok 1, 1, sprintf("index (%2d)", $_)
      for 19..21;
  }

  # check intermediate index not set
  ok(evcheck(sub { $n = $x->a_isset(3) }, 'index (22)'), 1, 'index (22)');
  ok ! $n;                                                      # index (23)

  ok evcheck(sub { %n = $x->a }, 'index (24)'), 1,               'index (24)';
  print STDERR Data::Dumper->Dump([\@n], [qw(@n)])
    if $ENV{TEST_DEBUG};
  ok keys %n, 7,                                                 'index (25)';
  ok $n{a}, 11,                                                  'index (26)';
  ok $n{c}, 13,                                                  'index (27)';
  ok $n{0}, 21,                                                  'index (28)';
  ok $n{1}, 45,                                                  'index (29)';
  ok $n{4}, 42,                                                  'index (30)';

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

=head2 Tests 126--149: count

=cut

{
  my ($n, @n, %n);

  ok evcheck(sub {%n=$x->a(a=>11,b=>12,c=>13); },'count ( 1)'),1,'count ( 1)';
  ok keys %n, 3,                                                 'count ( 2)';
  ok $n{a}, 11,                                                  'count ( 3)';
  ok $n{b}, 12,                                                  'count ( 4)';
  ok $n{c}, 13,                                                  'count ( 5)';
  ok evcheck(sub { $n = $x->a_count; }, 'count ( 6)'), 1,        'count ( 6)';
  ok $n, 3,                                                      'count ( 7)';

  ok(evcheck(sub { %n = $x->a(qw(a 14 b 15 c 16 d 17)); }, 'count ( 8)'),
   1,                                                            'count ( 8)');
  ok keys %n, 4,                                                 'count ( 9)';
  ok $n{a}, 14,                                                  'count (10)';
  ok $n{b}, 15,                                                  'count (11)';
  ok $n{c}, 16,                                                  'count (12)';
  ok $n{d}, 17,                                                  'count (13)';
  ok evcheck(sub { $n = $x->a_count; }, 'count (14)'), 1,        'count (14)';
  ok $n, 4,                                                      'count (15)';

  # lvalue support has been dropped (I can't find a consistent way to support
  ok evcheck(sub { $x->a_set(8, 19); }, 'count (16)'), 1,     'count (16)';
  ok evcheck(sub { $n = $x->a_count; }, 'count (17)'), 1,        'count (17)';
  ok $n, 5,                                                      'count (18)';

  ok(evcheck(sub { @n = $x->a_index(7,8) }, 'count (19)'), 1,    'count (19)');
  ok @n, 2,                                                      'count (20)';
  ok $n[0], undef,                                               'count (21)';
  ok $n[1], 19,                                                  'count (22)';

  # check intermediate index still not set
  ok(evcheck(sub { $n = $x->a_isset(6) }, 'count (23)'), 1, 'count (23)');
  ok ! $n                                                       # count (24)
}

# -------------------------------------

=head2 Tests 150--175: set

=cut

{
  my ($n, @n, %n);

  ok evcheck(sub {%n=$x->a(+{a=>11,b=>12,c=>13}); }, 'set ( 1)'),1,'set ( 1)';
  ok keys %n, 3,                                                   'set ( 2)';
  ok $n{a}, 11,                                                    'set ( 3)';
  ok $n{b}, 12,                                                    'set ( 4)';
  ok $n{c}, 13,                                                    'set ( 5)';

  ok evcheck(sub { $n = $x->a_set(c=>14,d=>15); }, 'set ( 6)'), 1, 'set ( 6)';
  ok $n, undef,                                                    'set ( 7)';

  ok(evcheck(sub { %n = $x->a; },   'set ( 8)'), 1,                'set ( 8)');
  ok keys %n, 4,                                                   'set ( 9)';
  ok $n{a}, 11,                                                    'set (10)';
  ok $n{b}, 12,                                                    'set (11)';
  ok $n{c}, 14,                                                    'set (12)';
  ok $n{d}, 15,                                                    'set (13)';
  ok evcheck(sub { $n = $x->a_count; },   'set (14)'), 1,          'set (14)';
  ok $n, 4,                                                        'set (15)';

  ok evcheck(sub {$n = $x->a_set([qw(a e)],[16,17])},'set (16)'),1,'set (16)';
  ok $n, undef,                                                    'set (17)';

  ok(evcheck(sub { %n = $x->a; },   'set (18)'), 1,                'set (18)');
  ok keys %n, 5,                                                   'set (19)';
  ok $n{a}, 16,                                                    'set (20)';
  ok $n{b}, 12,                                                    'set (21)';
  ok $n{c}, 14,                                                    'set (22)';
  ok $n{d}, 15,                                                    'set (23)';
  ok $n{e}, 17,                                                    'set (24)';
  ok evcheck(sub { $n = $x->a_count; },   'set (25)'), 1,          'set (25)';
  ok $n, 5,                                                        'set (26)';
}

# -------------------------------------

=head2 Tests 176--274: default

=cut

{
  my ($n, %n);
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([ hash =>
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
  ok $n, undef,                                                'default ( 5)';

  ok(evcheck(sub { $n = $x->df1; },       'default ( 6)'), 1,  'default ( 6)');
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok ref($n), 'HASH',                                          'default ( 7)';
  ok keys %$n, 0,                                              'default ( 8)';

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
  ok $n, 1,                                                    'default (18)';

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
  ok $n, 1,                                                    'default (27)';

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
  ok $n, 1,                                                    'default (44)';
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
  ok $n, 1,                                                    'default (67)';
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
  ok evcheck(sub { $x->df1_set(2, undef)},'default (81)'),1,'default (81)';
  ok(evcheck(sub { $n = $x->df1_isset; }, 'default (82)'), 1,  'default (82)');
  ok $n;                                                      # default (83)
  ok(evcheck(sub { $n = $x->df1_isset(0); }, 'default (84)'),1,'default (84)');
  ok $n;                                                      # default (85)
  ok(evcheck(sub { $n = $x->df1_isset(1); }, 'default (86)'),1,'default (86)');
  ok $n;                                                      # default (87)
  ok(evcheck(sub { $n = $x->df1_isset(2); }, 'default (88)'),1,'default (88)');
  ok $n;                                                      # default (89)
  ok evcheck(sub { $n = $x->df1_count }, 'default (90)'), 1,   'default (90)';
  ok $n, 1,                                                    'default (91)';
  ok evcheck(sub { $n = $x->df1_index(2) }, 'default (92)'), 1,'default (92)';
  ok $n, undef,                                                'default (93)';
  ok evcheck(sub { $n = $x->df1_index(1) }, 'default (94)'), 1,'default (94)';
  print STDERR Data::Dumper->Dump([$n], [qw($n)])
    if $ENV{TEST_DEBUG};
  ok $n, 7,                                                    'default (95)';

  ok evcheck(sub { %n = $x->df1 },         'default (96)'), 1, 'default (96)';
  ok keys %n, 2,                                               'default (97)';
  ok $n{1}, 7,                                                 'default (98)';
  ok $n{2}, undef,                                             'default (99)';
}

# -------------------------------------

=head2 Tests 275--295: default_ctor

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
  my ($n, %n);
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([hash =>
                                                 [{ -type => 'Y',
                                                    -default_ctor => 'new',
                                                  },
                                                  qw( df2 ),
                                                  { -type => 'Y',
                                                    -default_ctor =>
                                                      sub {
                                                        Y->new(undef,-3);
                                                      },
                                                  },
                                                  qw( df3 ),
                                                 ],
                                               ]);
                 }, 'default ( 1)'), 1,                   'default_ctor ( 1)');
  ok(evcheck(sub { $n = $x->df2_isset; }, 'default_ctor( 2)'), 1,
                                                          'default_ctor ( 2)');
  ok $n;                                                 # default_ctor ( 3)
  ok(evcheck(sub { $n = $x->df2_index(1)->value; }, 'default_ctor( 4)'), 1,
                                                          'default_ctor ( 4)');
  ok $n, 1,                                               'default_ctor ( 5)';
  # This actually creates two Y instances; one explicitly, and one not implictly
  # by the _index method defaulting one (since it can't see the incoming)
  # XXX not anymore XXX
  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  ok(evcheck(sub { $x->df2_set(2, Y->new); }, 'default_ctor( 6)'), 1,
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

  ok evcheck(sub { %n = $x->df2 }, 'default_ctor (18)'),1,'default_ctor (18)';
  ok keys %n, 1,                                          'default_ctor (19)';
  ok ref($n{2}), 'Y',                                     'default_ctor (20)';
  ok $n{2}->value, 3,                                     'default_ctor (21)';
}

# -------------------------------------

=head2 Tests 296--320: forward

=cut

{
  my ($n, @n, %n);
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([hash =>
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
  ok(evcheck(sub { $x->st1(a=>4); }, 'forward ( 4)'), 0,       'forward ( 4)');
  ok(evcheck(sub { @n = $x->st1; }, 'forward ( 5)'), 1,        'forward ( 5)');
  ok @n, 0,                                                    'forward ( 6)';
  ok(evcheck(sub { $n = $x->st1_isset; }, 'forward ( 7)'), 1,  'forward ( 7)');
  ok ! $n;                                                    # forward ( 8)
  ok(evcheck(sub { $x->st1(b=>undef); }, 'forward ( 9)'), 1,   'forward ( 9)');
  ok(evcheck(sub { $n = $x->st1_isset; }, 'forward (10)'), 1,  'forward (10)');
  ok $n;                                                      # forward (11)
  ok(evcheck(sub { @n = $x->st1; }, 'forward (12)'), 1,        'forward (12)');
  ok @n, 2,                                                    'forward (13)';
  ok $n[1], undef,                                             'forward (14)';
  ok(evcheck(sub { $x->st1_set(script=>stat(catfile($Bin,$Script)),
                               bin   =>stat(catfile($Bin))) }, 'forward (15)'),
     1,                                                        'forward (15)');
  print STDERR Data::Dumper->Dump([$x],[qw(x)])
    if $ENV{TEST_DEBUG};
  print STDERR B::Deparse->new('-p', '-sC')->coderef2text(\&X::mode), "\n"
    if $ENV{TEST_DEBUG};
  ok(evcheck(sub { %n = $x->mode; }, 'forward (16)'), 1,       'forward (16)');
  print STDERR Data::Dumper->Dump([\%n],[qw(n)])
    if $ENV{TEST_DEBUG};

  ok keys %n, 3,                                               'forward (17)';
  ok S_ISREG($n{script}), 1,                                   'forward (18)';
  ok S_ISDIR($n{bin}), 1,                                      'forward (19)';
  ok exists $n{b};                                            # forward (20)
  ok ! defined $n{b};                                         # forward (21)

  ok(evcheck(sub { $n = $x->size; }, 'forward (22)'), 1,       'forward (22)');
  ok ref $n, 'HASH',                                           'forward (23)';
  ok keys %$n, 3,                                              'forward (24)';
  {
    sysopen my $fh, catfile($Bin,$Script), O_RDONLY;
    local $/ = undef;
    my $text = <$fh>;
    close $fh;
    ok $n->{script}, length($text),                            'forward (25)';
  }
}

# -------------------------------------

=head2 Tests 321--323: forward_args

=cut

{
  my $n;
  # Instantiate st2 as IO::File, which is a subclass of IO::Handle.  This
  # should be fine
  ok(evcheck(sub { $x->st2(script => IO::File->new(catfile($Bin,$Script))) },
             'forward_args ( 1)'), 1,                     'forward_args ( 1)');
  ok(evcheck(sub { $x->read($n, 30); }, 'forward_args ( 2)'), 1,
                                                          'forward_args ( 2)');
  ok $n, '# (X)Emacs mode: -*- cperl -*-',                'forward_args ( 3)';
}

# -------------------------------------

=head2 Tests 324--364: manipulate

=cut

{
  my ($n, @n, %n, @p);
  ok(evcheck(sub {$x->a(a=>11,b=>12,c=>13); },  'manipulate ( 1)'),1,
                                                            'manipulate ( 1)');

  ok(evcheck(sub { @n = sort $x->a_keys },  'manipulate ( 2)'), 1,
                                                            'manipulate ( 2)');
  ok @n, 3,                                                 'manipulate ( 3)';
  ok $n[0], 'a',                                            'manipulate ( 4)';
  ok $n[1], 'b',                                            'manipulate ( 5)';
  ok $n[2], 'c',                                            'manipulate ( 6)';

  ok(evcheck(sub { $n = $x->a_keys },  'manipulate ( 7)'), 1,
                                                            'manipulate ( 7)');
  ok @$n, 3,                                                'manipulate ( 8)';
  @p = sort @$n;
  ok $p[0], 'a',                                            'manipulate ( 9)';
  ok $p[1], 'b',                                            'manipulate (10)';
  ok $p[2], 'c',                                            'manipulate (11)';

  ok(evcheck(sub { @n = sort {$a<=>$b} $x->a_values },  'manipulate (12)'), 1,
                                                            'manipulate (12)');
  ok @n, 3,                                                 'manipulate (13)';
  ok $n[0], 11,                                             'manipulate (14)';
  ok $n[1], 12,                                             'manipulate (15)';
  ok $n[2], 13,                                             'manipulate (16)';

  ok(evcheck(sub { $n = $x->a_values },  'manipulate (17)'), 1,
                                                            'manipulate (17)');
  ok @$n, 3,                                                'manipulate (18)';
  @p = sort {$a<=>$b} @$n;
  ok $p[0], 11,                                             'manipulate (19)';
  ok $p[1], 12,                                             'manipulate (20)';
  ok $p[2], 13,                                             'manipulate (21)';

  ok(evcheck(sub { while(my($k,$v)=$x->a_each){$n{$v}=$k} },
             'manipulate (22)'),
     1,                                                     'manipulate (22)');
  ok keys %n, 3,                                            'manipulate (23)';
  ok $n{11}, 'a',                                           'manipulate (24)';
  ok $n{12}, 'b',                                           'manipulate (25)';
  ok $n{13}, 'c',                                           'manipulate (26)';

  ok(evcheck(sub { $n = $x->a_exists('a') },  'manipulate (27)'), 1,
                                                            'manipulate (27)');
  ok $n, 1,                                                 'manipulate (28)';
  ok(evcheck(sub { $n = $x->a_exists('a', 'c') },  'manipulate (29)'), 1,
                                                            'manipulate (30)');
  ok $n, 1,                                                 'manipulate (31)';
  ok(evcheck(sub { $n = $x->a_exists('d') },  'manipulate (31)'), 1,
                                                            'manipulate (32)');
  ok $n, undef,                                             'manipulate (30)';
  ok(evcheck(sub { $n = $x->a_exists('a', 'd') },  'manipulate (33)'), 1,
                                                            'manipulate (33)');
  ok $n, undef,                                             'manipulate (34)';

  ok(evcheck(sub { $n = $x->a_delete('b') },  'manipulate (35)'), 1,
                                                            'manipulate (35)');
  ok(evcheck(sub { %n = $x->a },  'manipulate (36)'), 1,
                                                            'manipulate (36)');
  ok keys %n, 2,                                            'manipulate (37)';
  @p = sort keys %n;
  ok $p[0], 'a',                                            'manipulate (38)';
  ok $p[1], 'c',                                            'manipulate (39)';

  ok(evcheck(sub { $n = $x->a_delete() },  'manipulate (40)'), 1,
                                                            'manipulate (40)');
  ok keys %n, 2,                                            'manipulate (41)';
}

# -------------------------------------

=head2 Tests 365-405: tie

=cut

{
  # @z is an audit trail
  my @z;
  package Z;
  use Tie::Hash;
  use base qw( Tie::StdHash );
  sub TIEHASH  { push @z, [ 'TIEHASH'       ]; $_[0]->SUPER::TIEHASH          }
  sub FETCH    { push @z, [ FETCH => $_[1]  ]; $_[0]->SUPER::FETCH($_[1])     }
  sub STORE    { push @z, [ STORE => @_[1,2]]; $_[0]->SUPER::STORE(@_[1,2])   }
  # Strangely, Tie::StdHash doesn't have a DESTROY method
  sub DESTROY  { push @z, [ 'DESTROY'       ]; } #$_[0]->SUPER::DESTROY       }
  package main;

  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([hash =>
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
  $x->tie1_set(script => $stat1);

  ok @z, 2,                                                        'tie ( 3)';
  ok $z[0][0], 'TIEHASH',                                          'tie ( 4)';
  ok $z[1][0], 'STORE'   ,                                         'tie ( 5)';
  ok $z[1][1], 'script'  ,                                         'tie ( 6)';
  ok $z[1][2], $stat1    ,                                         'tie ( 7)';

  my $y;
  ok evcheck(sub { $y = $x->tie1_index('script') }, 'tie ( 8)'), 1,'tie ( 8)';
  ok $y, $stat1,                                                   'tie ( 9)';
  ok @z, 3,                                                        'tie (10)';
  ok $z[2][0], 'FETCH',                                            'tie (11)';
  ok $z[2][1], 'script',                                           'tie (12)';

  ok evcheck(sub { $y = $x->tie1_index(2) }, 'tie (13)'), 1,       'tie (13)';
  ok $y, undef,                                                    'tie (14)';
  ok @z, 4,                                                        'tie (15)';
  ok $z[3][0], 'FETCH',                                            'tie (16)';
  ok $z[3][1], 2,                                                  'tie (17)';

  ok evcheck(sub { $x->tie1_set('bin', $stat2) }, 'tie (18)'), 1,  'tie (18)';
  ok @z, 5,                                                        'tie (19)';
  ok $z[4][0], 'STORE',                                            'tie (20)';
  ok $z[4][1], 'bin',                                              'tie (21)';
  ok $z[4][2], $stat2,                                             'tie (22)';

  ok evcheck(sub { $y = $x->tie1 }, 'tie (23)'), 1,                'tie (23)';
  ok ref $y, 'HASH',                                               'tie (24)';
  ok keys %$y, 2,                                                  'tie (25)';
  ok $y->{script}, $stat1,                                         'tie (26)';
  ok $y->{bin}, $stat2,                                            'tie (27)';
  ok @z, 7,                                                        'tie (28)';
  ok $z[$_][0], 'FETCH',                          sprintf 'tie (%02d)', $_+24
    for 5..6;
  my @x = sort $z[5][1], $z[6][1];
  ok $x[0], 'bin',                                                 'tie (31)';
  ok $x[1], 'script',                                              'tie (32)';

  ok evcheck(sub { $x->tie1_reset }, 'tie (33)'), 1,               'tie (33)';
  ok @z, 8,                                                        'tie (34)';
  ok $z[7][0], 'DESTROY',                                          'tie (35)';

  ok evcheck(sub { $y = $x->tie1_count }, 'tie (36)'), 1,          'tie (36)';
  ok $y, undef,                                                    'tie (37)';
  ok @z, 8,                                                        'tie (38)';

  ok evcheck(sub { $y = $x->tie1_index(2) }, 'tie (39)'), 1,       'tie (39)';
  ok $y, undef,                                                    'tie (40)';
  ok @z, 8,                                                        'tie (41)';

  # Beware that indexing items off the end of @z above will auto-vivify the
  # corresponding entries, so if you see empty members of @z, that's possibly
  # the cause
  print Dumper \@z, $x
    if $ENV{TEST_DEBUG};
}

# -------------------------------------

=head2 Tests 406-409 : void set

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

=head2 Tests 410--426 : clear

=cut

{
  my $n;
  ok(evcheck(sub { $x->a_reset; }, 'clear ( 1)'), 1,             'clear ( 1)');
  ok(evcheck(sub { $n = $x->a_isset; }, 'clear ( 1)'), 1,        'clear ( 2)');
  ok ! $n;                                                      # clear ( 3)
  ok(evcheck(sub { $x->a(a => 4, b => 5); }, 'clear ( 3)'), 1,   'clear ( 4)');
  ok(evcheck(sub { $x->a_clear('a'); }, 'clear ( 4)'), 1,        'clear ( 5)');
  ok(evcheck(sub { $n = $x->a; }, 'clear ( 5)'), 1,              'clear ( 6)');
  ok keys %$n, 2,                                                'clear ( 7)';
  ok exists $n->{a};                                            # clear ( 8)
  ok exists $n->{b};                                            # clear ( 9)
  ok $n->{a}, undef,                                             'clear (10)';
  ok $n->{b}, 5,                                                 'clear (11)';
  ok(evcheck(sub { $x->a(a=>4,b=>5,c=>6); }, 'clear (11)'), 1,   'clear (12)');
  ok(evcheck(sub { $x->a_clear; }, 'clear (12)'), 1,             'clear (13)');
  ok(evcheck(sub { $n = $x->a; }, 'clear (13)'), 1,              'clear (14)');
  ok keys %$n, 0,                                                'clear (15)';
  ok(evcheck(sub { $n = $x->a_isset('a'); }, 'clear (15)'), 1,   'clear (16)');
  ok ! $n;                                                      # clear (17)
}

# -------------------------------------

=head2 Tests 427--439: default_ctor (arg)

=cut

{
  package S;
  my $count = 0;
  sub new {
    my ($class, $arg) = @_;
    my $self = $arg->a_index("a");
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
  my ($n, %n);
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([hash =>
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
  $x->a(a=>3);
  ok(evcheck(sub { $n = $x->dfx_index(1)->value; }, 'default_ctor (arg)( 4)'), 1,
                                                    'default_ctor (arg) ( 4)');
  ok $n, 3,                                         'default_ctor (arg) ( 5)';
  # This actually creates two Y instances; one explicitly, and one not implictly
  # by the _index method defaulting one (since it can't see the incoming)
  # XXX not anymore XXX
  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  my $xx = bless {}, 'X'; $xx->a(a=>2);
  ok(evcheck(sub { $x->dfx_set(2, S->new($xx)); }, 'default_ctor (arg)( 6)'), 1,
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

# _get
# _set

# _isset(n) _isset(n,m,l)
# _reset(n) _reset(n,m,l)

# _setref
# _grep
# _map
# _for
# _areset

# ----------------------------------------------------------------------------
