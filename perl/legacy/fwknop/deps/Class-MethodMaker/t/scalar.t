# (X)Emacs mode: -*- cperl -*-

use strict;

=head1 Unit Test Package for Class::MethodMaker

This package tests the scalar type of Class::MethodMaker

=cut

use Data::Dumper                qw( Dumper );
use Fatal                  1.02 qw( sysopen close );
use Fcntl                  1.03 qw( :DEFAULT );
use File::Spec::Functions       qw( catfile );
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
  plan tests  => 314,
       todo   => [],
}

# ----------------------------------------------------------------------------

=head2 Test 1: compilation

This test confirms that the test script and the modules it calls compiled
successfully.

=cut

package X;

use Class::MethodMaker
  [ scalar => [qw/ a b -static s /],
  ];

package main;

ok 1, 1, 'compilation';

# -------------------------------------

=head2 Test 2: bless

=cut

my $x;
ok evcheck(sub { $x = bless {}, 'X'; }, 'bless ( 1)'), 1,        'bless ( 1)';

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
  ok(evcheck(sub { $n = $x->b_isset; }, 'simple non-static ( 3)'), 1,
                                                     'simple non-static ( 3)');
  ok ! $n;                                          # simple non-static ( 4)
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
  ok(evcheck(sub { $n = $x->b_isset; }, 'simple non-static (12)'), 1,
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

=head2 Tests 23--35: lvalue

lvalue support has been dropped (I can't find a consistent way to support it
in the presence of read callbacks).

=cut

TEST_23:

if ( 0 ) {
  my $n;

  # Test lvalueness of b
  ok(evcheck(sub { $x->b = (); }, 'lvalue ( 1)'), 1,            'lvalue ( 1)');
  ok(evcheck(sub { $n = $x->b_isset; }, 'lvalue ( 2)'), 1,      'lvalue ( 2)');
  ok $n;                                                       # lvalue ( 3)
  ok(evcheck(sub { $n = $x->b; }, 'lvalue ( 4)'), 1,            'lvalue ( 4)');
  ok $n, undef,                                                 'lvalue ( 5)';
  ok(evcheck(sub { $x->b = undef; }, 'lvalue ( 6)'), 1,         'lvalue ( 6)');
  ok(evcheck(sub { $n = $x->b_isset; }, 'lvalue ( 7)'), 1,      'lvalue ( 7)');
  ok $n;                                                       # lvalue ( 8)
  ok(evcheck(sub { $n = $x->b; }, 'lvalue ( 9)'), 1,            'lvalue ( 9)');
  ok $n, undef,                                                 'lvalue (10)';
  ok(evcheck(sub { $x->b = 13 }, 'lvalue (11)'), 1,             'lvalue (11)');
  ok(evcheck(sub { $n = $x->b; }, 'lvalue (12)'), 1,            'lvalue (12)');
  ok $n, 13,                                                    'lvalue (13)';
} else {
  ok 1, 1, sprintf 'lvalue (-%2d)', $_
    for 1..13;
}

# -------------------------------------

=head2 Tests 36--51: typed

=cut

TEST_36: {
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([scalar =>
                                                 [{ -type => 'File::stat' },
                                                  qw( st ), ]])},
             'typed ( 1)'),
     1,                                                          'typed ( 1)');
  ok(evcheck(sub { $n = $x->st_isset; }, 'typed ( 2)'), 1,       'typed ( 2)');
  ok ! $n;                                                      # typed ( 3)
  ok(evcheck(sub { $x->st(4); }, 'typed ( 4)'), 0,               'typed ( 4)');
  ok(evcheck(sub { $n = $x->st; }, 'typed ( 5)'), 1,             'typed ( 5)');
  ok $n, undef,                                                  'typed ( 6)';
  ok(evcheck(sub { $n = $x->st_isset; }, 'typed ( 7)'), 1,       'typed ( 7)');
  ok ! $n;                                                      # typed ( 8)
  ok(evcheck(sub { $x->st(undef); }, 'typed ( 9)'), 1,           'typed ( 9)');
  ok(evcheck(sub { $n = $x->st_isset; }, 'typed (10)'), 1,       'typed (10)');
  ok $n;                                                        # typed (11)
  ok(evcheck(sub { $n = $x->st; }, 'typed (12)'), 1,             'typed (12)');
  ok $n, undef,                                                  'typed (13)';
  ok(evcheck(sub { $x->st(stat catfile($Bin,$Script)) }, 'typed (14)'),
     1,                                                          'typed (14)');
  ok(evcheck(sub { $n = $x->st; }, 'typed (15)'), 1,             'typed (15)');
  ok S_ISREG($n->mode), 1,                                       'typed (16)';

}

# -------------------------------------

=head2 Tests 52--69: forward

=cut

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([scalar =>
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
  ok(evcheck(sub { $n = $x->st1; }, 'forward ( 5)'), 1,        'forward ( 5)');
  ok $n, undef,                                                'forward ( 6)';
  ok(evcheck(sub { $n = $x->st1_isset; }, 'forward ( 7)'), 1,  'forward ( 7)');
  ok ! $n;                                                    # forward ( 8)
  ok(evcheck(sub { $x->st1(undef); }, 'forward ( 9)'), 1,      'forward ( 9)');
  ok(evcheck(sub { $n = $x->st1_isset; }, 'forward (10)'), 1,  'forward (10)');
  ok $n;                                                      # forward (11)
  ok(evcheck(sub { $n = $x->st1; }, 'forward (12)'), 1,        'forward (12)');
  ok $n, undef,                                                'forward (13)';
  ok(evcheck(sub { $x->st1(stat catfile($Bin,$Script)) }, 'forward (14)'),
     1,                                                        'forward (14)');
  ok(evcheck(sub { $n = $x->mode; }, 'forward (15)'), 1,       'forward (15)');
  ok S_ISREG($n), 1,                                           'forward (16)';
  ok(evcheck(sub { $n = $x->size; }, 'forward (17)'), 1,       'forward (17)');
  {
    sysopen my $fh, catfile($Bin,$Script), O_RDONLY;
    local $/ = undef;
    my $text = <$fh>;
    close $fh;
    ok $n, length($text),                                     'forward (18)';
  }
}

# -------------------------------------

=head2 Tests 70--72: forward_args

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

=head2 Tests 73--85: default

=cut

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([scalar =>
                                                 [{ -default => 7,
                                                  },
                                                  qw( df1 ),
                                                 ],
                                               ]);
                 }, 'default ( 1)'), 1,                        'default ( 1)');
  ok(evcheck(sub { $n = $x->df1_isset; }, 'default ( 2)'), 1,  'default ( 2)');
  ok $n;                                                      # default ( 3)
  ok(evcheck(sub { $n = $x->df1; }, 'default ( 4)'), 1,        'default ( 4)');
  ok $n, 7,                                                    'default ( 5)';

  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  if ( 0 ) {
    ok(evcheck(sub { $x->df1 = 13; }, 'default ( 6)'), 1,      'default ( 6)');
    ok(evcheck(sub { $n = $x->df1; }, 'default ( 7)'), 1,      'default ( 7)');
    ok $n, 13,                                                 'default ( 8)';
  } else {
    ok 1, 1, sprintf 'default (-%2d)', $_
      for 6..8;
  }
  ok(evcheck(sub { $x->df1_reset; }, 'default ( 9)'), 1,       'default ( 9)');
  ok(evcheck(sub { $n = $x->df1_isset; }, 'default (10)'), 1,  'default (10)');
  ok $n;                                                      # default (11)
  ok(evcheck(sub { $n = $x->df1; }, 'default (12)'), 1,        'default (12)');
  ok $n, 7,                                                    'default (13)';
}

# -------------------------------------

=head2 Tests 86--102: default_ctor

=cut

{
  package Y;
  my $count;
  sub new {
    my $class = shift;
    my $i = shift;
    my $self = @_ ? $_[0] : ++$count;
    return bless \$self, $class;
  }

  sub value {
    return ${$_[0]};
  }
}

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([scalar =>
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
  ok(evcheck(sub { $n = $x->df2->value; }, 'default_ctor( 4)'), 1,
                                                          'default_ctor ( 4)');
  ok $n, 1,                                               'default_ctor ( 5)';

  # lvalue support has been dropped (I can't find a consistent way to support
  # it in the presence of read callbacks).
  if ( 0 ) {
    ok(evcheck(sub { $x->df2 = Y->new; }, 'default_ctor( 6)'), 1,
                                                          'default_ctor ( 6)');
    ok(evcheck(sub { $n = $x->df2->value; }, 'default_ctor( 7)'), 1,
                                                          'default_ctor ( 7)');
    ok $n, 2,                                             'default_ctor ( 8)';
  } else {
    ok (evcheck(sub { $x->df2(Y->new); }, 'default_ctor(- 6)'), 1,
                                                         'default_ctor (- 6)');
    ok 1, 1, sprintf 'default_ctor (-%2d)', $_
      for 7..8
  }

  ok(evcheck(sub { $x->df2_reset; },'default_ctor( 9)'), 1,
                                                          'default_ctor ( 9)');
  ok(evcheck(sub { $n = $x->df2_isset; }, 'default_ctor(10)'), 1,
                                                          'default_ctor (10)');
  ok $n;                                                 # default_ctor (11)
  ok(evcheck(sub { $n = $x->df2->value; }, 'default_ctor(12)'), 1,
                                                          'default_ctor (12)');
  ok $n, 3,                                               'default_ctor (13)';
  ok(evcheck(sub { $n = $x->df3_isset; }, 'default_ctor(14)'), 1,
                                                          'default_ctor (14)');
  ok $n;                                                 # default_ctor (15)
  ok(evcheck(sub { $n = $x->df3->value; }, 'default_ctor(16)'), 1,
                                                          'default_ctor (16)');
  ok $n, -3,                                              'default_ctor (17)';
}

# -------------------------------------

=head2 Tests 103--114: !syntax

=cut

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import
                     ([scalar => [qw/ -static bs1 !static bs2 /],]);
                 }, '!syntax ( 1)'), 1,                        '!syntax ( 1)');
  my $y;
  ok evcheck(sub { $y = bless {}, 'X'; }, '!syntax ( 2)'), 1,  '!syntax ( 2)';

  ok evcheck(sub { $x->bs1(7); }, '!syntax ( 3)'), 1,          '!syntax ( 3)';
  ok evcheck(sub { $n = $x->bs1; }, '!syntax ( 4)'), 1,        '!syntax ( 4)';
  ok $n, 7,                                                    '!syntax ( 5)';
  ok evcheck(sub { $n = $y->bs1; }, '!syntax ( 6)'), 1,        '!syntax ( 6)';
  ok $n, 7,                                                    '!syntax ( 7)';
  ok evcheck(sub { $x->bs2(9); }, '!syntax ( 8)'), 1,          '!syntax ( 8)';
  ok evcheck(sub { $n = $x->bs2; }, '!syntax ( 9)'), 1,        '!syntax ( 9)';
  ok $n, 9,                                                    '!syntax (10)';
  ok evcheck(sub { $n = $y->bs2; }, '!syntax (11)'), 1,        '!syntax (11)';
  ok $n, undef,                                                '!syntax (12)';
}

# -------------------------------------

=head2 Tests 115--126: nested scope

=cut

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import
                     ([scalar => [[qw/ -static bs3 /], 'bs4'],]);
                 }, 'nested scope ( 1)'), 1,              'nested scope ( 1)');
  my $y;
  ok(evcheck(sub { $y = bless {}, 'X'; }, 'nested scope ( 2)'), 1,
                                                          'nested scope ( 2)');

  ok evcheck(sub { $x->bs3(7); }, 'nested scope ( 3)'), 1,'nested scope ( 3)';
  ok(evcheck(sub { $n = $x->bs3; }, 'nested scope ( 4)'), 1,
                                                          'nested scope ( 4)');
  ok $n, 7,                                               'nested scope ( 5)';
  ok(evcheck(sub { $n = $y->bs3; }, 'nested scope ( 6)'), 1,
                                                          'nested scope ( 6)');
  ok $n, 7,                                               'nested scope ( 7)';
  ok evcheck(sub { $x->bs4(9); }, 'nested scope ( 8)'), 1,'nested scope ( 8)';
  ok(evcheck(sub { $n = $x->bs4; }, 'nested scope ( 9)'), 1,
                                                          'nested scope ( 9)');
  ok $n, 9,                                               'nested scope (10)';
  ok(evcheck(sub { $n = $y->bs4; }, 'nested scope (11)'), 1,
                                                          'nested scope (11)');
  ok $n, undef,                                           'nested scope (12)';
}

# -------------------------------------

=head2 Tests 127--130: simple name

=cut

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import
                     ([scalar => 'simple',]);
                 }, 'simple name ( 1)'), 1,                'simple name ( 1)');

  ok evcheck(sub { $x->simple(7); }, 'simple name ( 2)'),1,'simple name ( 2)';
  ok evcheck(sub { $n = $x->simple },'simple name ( 3)'),1,'simple name ( 3)';
  ok $n, 7,                                                'simple name ( 4)';
}

# -------------------------------------

=head2 Tests 131--142: repeated calls

=cut

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import
                     ([scalar => [qw/ -static bs5/ ],
                       scalar => 'bs6'
                      ]);
                 }, 'repeated calls ( 1)'), 1,          'repeated calls ( 1)');
  my $y;
  ok(evcheck(sub { $y = bless {}, 'X'; }, 'repeated calls ( 2)'), 1,
                                                        'repeated calls ( 2)');

  ok evcheck(sub { $x->bs5(7)},'repeated calls ( 3)'),1,'repeated calls ( 3)';
  ok(evcheck(sub { $n = $x->bs5; }, 'repeated calls ( 4)'), 1,
                                                        'repeated calls ( 4)');
  ok $n, 7,                                             'repeated calls ( 5)';
  ok(evcheck(sub { $n = $y->bs5; }, 'repeated calls ( 6)'), 1,
                                                        'repeated calls ( 6)');
  ok $n, 7,                                             'repeated calls ( 7)';
  ok evcheck(sub { $x->bs6(9)},'repeated calls ( 8)'),1,'repeated calls ( 8)';
  ok(evcheck(sub { $n = $x->bs6; }, 'repeated calls ( 9)'), 1,
                                                        'repeated calls ( 9)');
  ok $n, 9,                                             'repeated calls (10)';
  ok(evcheck(sub { $n = $y->bs6; }, 'repeated calls (11)'), 1,
                                                        'repeated calls (11)');
  ok $n, undef,                                         'repeated calls (12)';
}

# -------------------------------------

=head2 Tests 143--153: *_clear

=cut

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import
                     ([scalar => [{'*_clear' => '*_clear'}, 'xc1'],]);
                 }, '*_clear ( 1)'), 1,                        '*_clear ( 1)');

  ok evcheck(sub { $x->xc1(7); }, '*_clear ( 2)'), 1,          '*_clear ( 2)';
  ok evcheck(sub { $n = $x->xc1 }, '*_clear ( 3)'), 1,         '*_clear ( 3)';
  ok $n, 7,                                                    '*_clear ( 4)';
  ok evcheck(sub { $n = $x->xc1_isset }, '*_clear ( 5)'), 1,   '*_clear ( 5)';
  ok $n;                                                      # *_clear ( 6)
  ok evcheck(sub { $x->xc1_clear; }, '*_clear ( 7)'), 1,       '*_clear ( 7)';
  ok evcheck(sub { $n = $x->xc1 }, '*_clear ( 8)'), 1,         '*_clear ( 8)';
  ok $n, undef,                                                '*_clear ( 9)';
  ok evcheck(sub { $n = $x->xc1_isset }, '*_clear (10)'), 1,   '*_clear (10)';
  ok $n;                                                      # *_clear (11)
}

# -------------------------------------

=head2 Tests 154--202: rename

=cut

{
  my $n;
  ok(evcheck(sub { package Z;
                   Class::MethodMaker->import
                     ([ scalar => [[{'*_get' => 'get_*', '*_set' => 'set_*'},
                                    qw/ a -static b /],
                                   'c'],
                      ])
                 }, '*_clear ( 1)'), 1,                         'rename ( 0)');

  my ($x, $y);
  ok evcheck(sub { $x = bless {}, 'Z'; }, 'rename ( 1)'), 1,    'rename ( 1)';
  ok evcheck(sub { $y = bless {}, 'Z'; }, 'rename ( 1)'), 1,    'rename ( 2)';

  {
    # Perl 5.6.1 gets a bit over-zealous with the used only once warnings.
    no warnings;

    ok   defined *{Z::get_a}{CODE};                            # rename ( 3)
    ok ! defined *{Z::a_get}{CODE};                            # rename ( 4)
    ok   defined *{Z::get_b}{CODE};                            # rename ( 5)
    ok ! defined *{Z::b_get}{CODE};                            # rename ( 6)

    ok   defined *{Z::a}{CODE};                                # rename ( 7)
    ok   defined *{Z::a_reset}{CODE};                          # rename ( 8)
    ok   defined *{Z::a_isset}{CODE};                          # rename ( 9)
    ok ! defined *{Z::a_ref}{CODE};                            # rename (10)

    ok   defined *{Z::b}{CODE};                                # rename (11)
    ok   defined *{Z::b_reset}{CODE};                          # rename (12)
    ok   defined *{Z::b_isset}{CODE};                          # rename (13)
    ok ! defined *{Z::b_ref}{CODE};                            # rename (14)

    ok ! defined *{Z::get_c}{CODE};                            # rename (15)
    ok ! defined *{Z::c_get}{CODE};                            # rename (16)
    ok   defined *{Z::c}{CODE};                                # rename (17)
    ok   defined *{Z::c_reset}{CODE};                          # rename (18)
    ok   defined *{Z::c_isset}{CODE};                          # rename (19)
    ok ! defined *{Z::c_ref}{CODE};                            # rename (20)
  }

  ok evcheck(sub { $n = $x->set_a(7); }, 'rename (21)'), 1,     'rename (21)';
  ok $n, undef,                                                 'rename (22)';
  ok evcheck(sub { $n = $x->get_a(9); }, 'rename (23)'), 1,     'rename (23)';
  ok $n, 7,                                                     'rename (24)';
  ok evcheck(sub { $n = $x->get_a(9); }, 'rename (25)'), 1,     'rename (25)';
  ok $n, 7,                                                     'rename (26)';
  ok evcheck(sub { $n = $x->get_b(9); }, 'rename (27)'), 1,     'rename (27)';
  ok $n, undef,                                                 'rename (28)';
  ok evcheck(sub { $n = $y->get_a(9); }, 'rename (29)'), 1,     'rename (29)';
  ok $n, undef,                                                 'rename (30)';

  ok evcheck(sub { $n = $y->set_b(5); }, 'rename (31)'), 1,     'rename (31)';
  ok $n, undef,                                                 'rename (32)';
  ok evcheck(sub { $n = $y->get_b(9); }, 'rename (33)'), 1,     'rename (33)';
  ok $n, 5,                                                     'rename (34)';
  ok evcheck(sub { $n = $y->get_b(9); }, 'rename (35)'), 1,     'rename (35)';
  ok $n, 5,                                                     'rename (36)';
  ok evcheck(sub { $n = $x->get_b(9); }, 'rename (37)'), 1,     'rename (37)';
  ok $n, 5,                                                     'rename (38)';

  ok evcheck(sub { $n = $y->c(4); },     'rename (39)'), 1,     'rename (39)';
  ok $n, 4,                                                     'rename (40)';
  ok evcheck(sub { $n = $y->c(6); },     'rename (41)'), 1,     'rename (41)';
  ok $n, 6,                                                     'rename (42)';
  ok evcheck(sub { $n = $y->get_b(9); }, 'rename (43)'), 1,     'rename (43)';
  ok $n, 5,                                                     'rename (44)';
  ok evcheck(sub { $n = $x->get_a(9); }, 'rename (45)'), 1,     'rename (45)';
  ok $n, 7,                                                     'rename (46)';
  ok evcheck(sub { $n = $y->c; },        'rename (47)'), 1,     'rename (47)';
  ok $n, 6,                                                     'rename (48)';
}

# -------------------------------------

=head2 Tests 203--204: v1/2 check

=cut

{
  save_output('stderr', *STDERR{IO});
  ok(evcheck(sub {
               # Eval use statement to execute it at runtime
               eval qq{ package Z1;
                        use Class::MethodMaker
                        scalar => [qw/ a b -static s /],
                        ;
                      }; if ( $@ ) {
                        print STDERR $@;
                        die $@;
                      }
             }, 'v1/2 check ( 1)'), 0,                      'v1/2 check ( 1)');
  my $stderr = restore_output('stderr');
  print STDERR "stderr saved: $stderr\n"
    if $ENV{TEST_DEBUG};
  ok($stderr, qr!presenting your arguments to use/import!,
                                                            'v1/2 check ( 2)');
}

# -------------------------------------

=head2 Tests 205--221: tie

=cut

{
  # @z is an audit trail
  my @z;
  package W;
  use Tie::Scalar;
  use base qw( Tie::StdScalar );
  sub TIESCALAR { push @z, [ 'TIESCALAR'     ]; $_[0]->SUPER::TIESCALAR    }
  sub FETCH     { push @z, [ 'FETCH'         ]; $_[0]->SUPER::FETCH        }
  sub STORE     { push @z, [ STORE => $_[1]  ]; $_[0]->SUPER::STORE($_[1]) }
  sub DESTROY   { push @z, [ 'DESTROY'       ]; $_[0]->SUPER::DESTROY      }
  sub UNTIE     { push @z, [ UNTIE => $_[1]  ]; $_[0]->SUPER::UNTIE($_[1]) }
  package main;

  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([scalar =>
                                                 [{ -type      => 'File::stat',
                                                    -tie_class => 'W',
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
  $x->tie1($stat1);

  ok @z, 2,                                                        'tie ( 3)';
  ok $z[0][0], 'TIESCALAR',                                        'tie ( 4)';
  ok $z[1][0], 'STORE'   ,                                         'tie ( 5)';
  ok $z[1][1], $stat1    ,                                         'tie ( 6)';

  my $y;
  ok evcheck(sub { $y = $x->tie1 }, 'tie ( 7)'), 1,                'tie ( 7)';
  ok $y, $stat1,                                                   'tie ( 8)';
  ok @z, 3,                                                        'tie ( 9)';
  ok $z[2][0], 'FETCH',                                            'tie (10)';

  ok evcheck(sub { $x->tie1($stat2) }, 'tie (11)'), 1,             'tie (11)';
  ok @z, 4,                                                        'tie (12)';
  ok $z[3][0], 'STORE',                                            'tie (13)';
  ok $z[3][1], $stat2,                                             'tie (14)';

  ok evcheck(sub { $x->tie1_reset }, 'tie (15)'), 1,               'tie (15)';
  ok @z, 5,                                                        'tie (16)';
  ok $z[4][0], 'DESTROY',                                          'tie (17)';

  # Beware that indexing items off the end of @z above will auto-vivify the
  # corresponding entries, so if you see empty members of @z, that's possibly
  # the cause
  print Dumper \@z, $x
    if $ENV{TEST_DEBUG};
}

# -------------------------------------

=head Tests 222--230: tie_args

=cut

{
  package V;

  sub TIESCALAR {
    my $type = shift;
    my %args = @_ ;
    my $self={} ;
    if (defined $args{enum}) {
      # store all enum values in a hash. This way, checking
      # whether a value is present in the enum set is easier
      map {; $self->{enum}{$_} =  1 } @{$args{enum}} ;
    } else {
      die ref($self)," error: no enum values defined when calling init";
    }

    $self->{default} = $args{default};
    bless $self,$type;
  }

  sub STORE {
    my ($self,$value) = @_ ;
    die "cannot set ",ref($self)," item to $value. Expected ",
      join(' ',keys %{$self->{enum}})
        unless defined $self->{enum}{$value} ;
    # we may want to check other rules here ... TBD
    $self->{value} = $value ;
    return $value;
  }

  sub FETCH {
    my $self = shift ;
    return defined $self->{value} ? $self->{value} : $self->{default}  ;
  }

  package main;

  ok(evcheck(sub { package X;
                   Class::MethodMaker->import
                       ([scalar =>
                         [{ -tie_class => 'V',
                            -tie_args  => [enum    => [qw/A B C/],
                                           default => 'B'],
                          },
                          qw( tie2 ),
                         ]])},
             'tie_args ( 1)'),
     1,                                                       'tie_args ( 1)');

  ok $x->tie2, 'B',                                           'tie_args ( 2)';
  my $y;
  ok evcheck(sub { $y = $x->tie2('A') }, 'tie_args ( 3)'), 1, 'tie_args ( 3)';
  ok $y, 'A',                                                 'tie_args ( 4)';
  ok evcheck(sub { $y = $x->tie2 },      'tie_args ( 5)'), 1, 'tie_args ( 5)';
  ok $y, 'A',                                                 'tie_args ( 6)';
  ok evcheck(sub { $y = $x->tie2('D') }, 'tie_args ( 7)'), 0, 'tie_args ( 7)';
  ok evcheck(sub { $y = $x->tie2 },      'tie_args ( 8)'), 1, 'tie_args ( 8)';
  ok $y, 'A',                                                 'tie_args ( 9)';
}

# -------------------------------------

=head tests 231--251: read_cb

=cut

TEST_231: {
  my $n;

  ok(evcheck(sub { package X;
                   Class::MethodMaker->import
                       ([scalar =>
                         [{ -read_cb => sub { ($_[1]||0) + 1 } }, qw( rcb1 rcb2 ),]
                        ])},
             'read_cb ( 0)'),
     1,                                                        'read_cb ( 0)');

  ok(evcheck(sub { $n = $x->rcb1_isset; }, 'read_cb ( 1)'), 1,
                                                               'read_cb ( 1)');
  ok ! $n;                                                    # read_cb ( 2)
  ok(evcheck(sub { $n = $x->rcb2_isset; }, 'read_cb ( 3)'), 1,
                                                               'read_cb ( 3)');
  ok ! $n;                                                    # read_cb ( 4)
  ok(evcheck(sub { $x->rcb1(4); }, 'read_cb ( 5)'),
   1,                                                          'read_cb ( 5)');
  ok(evcheck(sub { $n = $x->rcb1; }, 'read_cb ( 6)'), 1,
                                                               'read_cb ( 6)');
  ok $n, 5,                                                    'read_cb ( 7)';
  ok(evcheck(sub { $n = $x->rcb1(7); }, 'read_cb ( 8)'), 1,
                                                               'read_cb ( 8)');
  ok $n, 8,                                                    'read_cb ( 9)';
  ok(evcheck(sub { $n = $x->rcb1_isset; }, 'read_cb (10)'), 1,
                                                               'read_cb (10)');
  ok $n;                                                      # read_cb (11)
  ok(evcheck(sub { $n = $x->rcb2_isset; }, 'read_cb (12)'), 1,
                                                               'read_cb (12)');
  ok ! $n;                                                    # read_cb (13)
  ok(evcheck(sub { $n = $x->rcb1_reset; }, 'read_cb (14)'), 1,
                                                               'read_cb (14)');
  ok(evcheck(sub { $n = $x->rcb1_isset; }, 'read_cb (15)'), 1,
                                                               'read_cb (15)');
  ok ! $n;                                                    # read_cb (16)
  ok(evcheck(sub { $n = $x->rcb1; }, 'read_cb (17)'), 1,
                                                               'read_cb (17)');
  ok $n, 1,                                                    'read_cb (18)';
  ok(evcheck(sub { $n = $x->rcb1_isset; }, 'read_cb (19)'), 1,
                                                               'read_cb (19)');
  ok ! $n;                                                    # read_cb (20)

}

# -------------------------------------

=head tests 252--274: store_cb

=cut

TEST_231: {
  my $n;

  ok(evcheck(sub { package X;
                   Class::MethodMaker->import
                       ([scalar =>
                         [{ -store_cb => sub { $_[1] + 1 } }, qw( scb1 scb2 ),]
                        ])},
            'store_cb ( 0)'),
     1,                                                       'store_cb ( 0)');

  ok(evcheck(sub { $n = $x->scb1_isset; }, 'store_cb ( 1)'), 1,
                                                              'store_cb ( 1)');
  ok ! $n;                                                   # store_cb ( 2)
  ok(evcheck(sub { $n = $x->scb2_isset; }, 'store_cb ( 3)'), 1,
                                                              'store_cb ( 3)');
  ok ! $n;                                                   # store_cb ( 4)
  ok(evcheck(sub { $x->scb1(4); }, 'store_cb ( 5)'),
   1,                                                         'store_cb ( 5)');
  ok(evcheck(sub { $n = $x->scb1; }, 'store_cb ( 6)'), 1,
                                                              'store_cb ( 6)');
  ok $n, 5,                                                   'store_cb ( 7)';
  ok(evcheck(sub { $n = $x->scb1(7); }, 'store_cb ( 8)'), 1,
                                                              'store_cb ( 8)');
  ok $n, 8,                                                   'store_cb ( 9)';
  ok(evcheck(sub { $n = $x->scb1_isset; }, 'store_cb (10)'), 1,
                                                              'store_cb (10)');
  ok $n;                                                     # store_cb (11)
  ok(evcheck(sub { $n = $x->scb2_isset; }, 'store_cb (12)'), 1,
                                                              'store_cb (12)');
  ok ! $n;                                                   # store_cb (13)
  ok(evcheck(sub { $n = $x->scb1_reset; }, 'store_cb (14)'), 1,
                                                              'store_cb (14)');
  ok(evcheck(sub { $n = $x->scb1_isset; }, 'store_cb (15)'), 1,
                                                              'store_cb (15)');
  ok ! $n;                                                   # store_cb (16)
  ok(evcheck(sub { $n = $x->scb1; }, 'store_cb (17)'), 1,
                                                              'store_cb (17)');
  ok $n, undef,                                               'store_cb (18)';
  ok(evcheck(sub { $n = $x->scb1_isset; }, 'store_cb (19)'), 1,
                                                              'store_cb (19)');
  ok ! $n;                                                   # store_cb (20)

  ok(evcheck(sub { $x->scb1(4); }, 'store_cb (21)'),
   1,                                                         'store_cb (21)');
  print Dumper $x
    if $ENV{TEST_DEBUG};
  ok $x->{scb1}, 5,                                            'store_cb(22)';
}

# -------------------------------------

=head Tests 275--294:

=cut

TEST_275: {
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([scalar =>
                                                 [{ -type => Class::MethodMaker::INTEGER },
                                                  qw( int ), ]])},
             'INTEGER ( 1)'),
     1,                                                        'INTEGER ( 1)');
  ok evcheck(sub { $n = $x->int_isset; }, 'INTEGER ( 2)'), 1,  'INTEGER ( 2)';
  ok ! $n;                                                    # INTEGER ( 3)
  ok evcheck(sub { $n = $x->int; }, 'INTEGER ( 4)'), 1,        'INTEGER ( 4)';
  ok $n, 0,                                                    'INTEGER ( 5)';
  ok evcheck(sub { $x->int(4); }, 'INTEGER ( 6)'), 1,          'INTEGER ( 6)';
  ok evcheck(sub { $n = $x->int; }, 'INTEGER ( 7)'), 1,        'INTEGER ( 7)';
  ok $n, 4,                                                    'INTEGER ( 8)';
  ok(evcheck(sub { $x->int("5x"); }, 'INTEGER ( 9)'), 1,       'INTEGER ( 9)');
  ok(evcheck(sub { $n = $x->int; }, 'INTEGER (10)'), 1,        'INTEGER (10)');
  ok $n, 5,                                                    'INTEGER (11)';
  ok(evcheck(sub { $n = $x->int_incr; }, 'INTEGER (12)'), 1,   'INTEGER (12)');
  ok $n, 6,                                                    'INTEGER (13)';
  # Check incr isn't installed by default on normal components
  ok(evcheck(sub { $n = $x->st_incr; }, 'INTEGER (14)'), 0,    'INTEGER (14)');
  ok(evcheck(sub { $n = $x->int_decr; }, 'INTEGER (15)'), 1,   'INTEGER (15)');
  ok $n, 5,                                                    'INTEGER (16)';
  ok(evcheck(sub { $n = $x->int_zero; }, 'INTEGER (17)'), 1,   'INTEGER (17)');
  ok $n, 0,                                                    'INTEGER (18)';
  ok(evcheck(sub { $n = $x->int; }, 'INTEGER (19)'), 1,        'INTEGER (19)');
  ok $n, 0,                                                    'INTEGER (20)';
}

# -------------------------------------

=head2 Tests 295--301: non-init ctor

This is to test that the default ctor or default is not assigned if a value is
supplied.  This would particularly be a problem with v1 compatiblity use where
a value is explcitly supplied to prevent 'new' being called because there is
no 'new' (if the ctor is called anyway, the program barfs).

=cut

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([scalar =>
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
  ok(evcheck(sub { $n = $x->nic; }, 'non-init ctor( 4)'), 0,
                                                         'non-init ctor ( 4)');
  ok(evcheck(sub { $x->nic(Y->new); }, 'non-init ctor( 5)'), 1,
                                                         'non-init ctor ( 5)');
  ok(evcheck(sub { $n = $x->nic; }, 'non-init ctor( 6)'), 1,
                                                         'non-init ctor ( 6)');
  ok ref $n, 'Y',                                        'non-init ctor ( 7)';
}

# -------------------------------------

=head2 Tests 302--314 default_ctor (arg)

=cut

TEST_302:

{
  package S;
  my $count;
  sub new {
    my ($class, $arg) = @_;

    die sprintf "Expected an X, got a '%s'\n", defined($arg) ? ref $arg : '*undef*'
      unless UNIVERSAL::isa($arg, 'X');
    my $self = $arg->int;
    return bless \$self, $class;
  }

  sub value {
    return ${$_[0]};
  }
}

{
  my $n;
  ok(evcheck(sub { package X;
                   Class::MethodMaker->import([scalar =>
                                                 [{ -type => 'S',
                                                    -default_ctor => 'new',
                                                  },
                                                  qw( dfx ),
                                                 ],
                                               ]);
                 }, 'default_ctor (arg)( 1)'), 1,   'default_ctor (arg) ( 1)');
  ok(evcheck(sub { $x->int(1) }, 'default_ctor (arg)( 2)'), 1,
                                                    'default_ctor (arg) ( 2)');
  ok(evcheck(sub { $n = $x->dfx_isset; }, 'default_ctor (arg)( 3)'), 1,
                                                    'default_ctor (arg) ( 3)');
  ok $n;                                           # default_ctor (arg) ( 4)
  ok(evcheck(sub { $n = $x->dfx->value; }, 'default_ctor (arg)( 5)'), 1,
                                                    'default_ctor (arg) ( 5)');
  ok $n, 1,                                         'default_ctor (arg) ( 6)';

  ok 1, 1, sprintf 'default_ctor (-%2d)', $_
    for 7..8;

  ok(evcheck(sub { $x->dfx_reset; },'default_ctor (arg)( 9)'), 1,
                                                    'default_ctor (arg) ( 9)');
  ok(evcheck(sub { $n = $x->dfx_isset; }, 'default_ctor (arg)(10)'), 1,
                                                    'default_ctor (arg) (10)');
  ok $n;                                           # default_ctor (arg) (11)
  ok(evcheck(sub { $n = $x->dfx->value; }, 'default_ctor (arg)(12)'), 1,
                                                    'default_ctor (arg) (12)');
  ok $n, 1,                                         'default_ctor (arg) (13)';
}

# ----------------------------------------------------------------------------
