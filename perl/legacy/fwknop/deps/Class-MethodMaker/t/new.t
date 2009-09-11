# (X)Emacs mode: -*- cperl -*-

use strict;

=head1 Unit Test Package for Class::MethodMaker

This package tests the scalar type of Class::MethodMaker

=cut

use FindBin                1.42 qw( $Bin $Script );
use Test                   1.13 qw( ok plan );

use lib $Bin;
use test qw( evcheck );

BEGIN {
  plan tests  => 32,
       todo   => [],
}

# ----------------------------------------------------------------------------

=head2 Test 1: compilation

This test confirms that the test script and the modules it calls compiled
successfully.

=cut

package X;

use Class::MethodMaker
  [ new => 'new',
    new => [qw/ -hash new_hash_init /],
    new => [qw/ -init new_with_init
                -hash new_both /],
  ];

my @args_in_init;
my $foo_called;
my $bar_called;

sub init {
  my ($self, @args) = @_;
  @args_in_init = @args;
}

sub foo {
  my ($self, $new) = @_;
  defined $new and $self->{'foo'} = $new;
  $foo_called = 1;
  $self->{'foo'};
}

sub bar {
  my ($self, $new) = @_;
  defined $new and $self->{'bar'} = $new;
  $bar_called = 1;
  $self->{'bar'};
}

package main;

ok 1, 1, 'compilation';

# -------------------------------------

=head Tests 2--3: new

=cut

{
  my $o;

  ok evcheck(sub { $o = new X; }, 'new ( 1)'), 1,                  'new ( 1)';
  ok ref $o, 'X',                                                  'new ( 2)';
}

# -------------------------------------

=head Tests 4--9: new_with_init

=cut

{
  my $o;
  my @args = (1, 2, 3);
  ok(evcheck(sub { $o = X->new_with_init(@args) }, 'new_with_init ( 1)'), 1,
                                                         'new_with_init ( 1)');
  ok ref $o, 'X',                                        'new_with_init ( 2)';
  ok $#args_in_init, $#args,                             'new_with_init ( 3)';
  ok $args_in_init[$_], $args[$_], sprintf('new_with_init (%2d)', $_+4)
    for 0..$#args;

  @args_in_init = ();
}

# -------------------------------------

=head Tests 10--15: new_hash_init

=cut

{
  my $o;
  ok(evcheck(sub { $o = X->new_hash_init( 'foo' => 123, 'bar' => 456 ) },
           'new_hash_init ( 1)'), 1,                     'new_hash_init ( 1)');
  ok ref $o, 'X',                                        'new_hash_init ( 2)';
  ok $foo_called, 1,                                     'new_hash_init ( 3)';
  ok $bar_called, 1,                                     'new_hash_init ( 4)';
  ok $o->foo, 123,                                       'new_hash_init ( 5)';
  ok $o->bar, 456,                                       'new_hash_init ( 6)';

  $foo_called = 0;
  $bar_called = 0;
}
# -------------------------------------

=head Tests 16--21: new_hash_init (taking hashref)

=cut

{
  my $o;
  $foo_called = 0;
  $bar_called = 0;

  ok(evcheck(sub { $o = X->new_hash_init({ 'foo' => 111, 'bar' => 444 }) },
           'new_hash_init (taking hashref) ( 1)'), 1,
                                        'new_hash_init (taking hashref) ( 1)');
  ok ref $o, 'X',                       'new_hash_init (taking hashref) ( 2)';
  ok $foo_called, 1,                    'new_hash_init (taking hashref) ( 3)';
  ok $bar_called, 1,                    'new_hash_init (taking hashref) ( 4)';
  ok $o->foo, 111,                      'new_hash_init (taking hashref) ( 5)';
  ok $o->bar, 444,                      'new_hash_init (taking hashref) ( 6)';

  $foo_called = 0;
  $bar_called = 0;
}

# -------------------------------------

=head Tests 22--32: new_hash_init (with init)

=cut

{
  my $o;

  my @args = ('foo' => 987, 'bar' => 654);
  ok(evcheck(sub { $o = X->new_both(@args) },
                'new_hash_init (with init) ( 1)'), 1,
                                             'new_hash_init (with init) ( 1)');
  ok ref $o, 'X',                            'new_hash_init (with init) ( 2)';
  ok $foo_called, 1,                         'new_hash_init (with init) ( 3)';
  ok $bar_called, 1,                         'new_hash_init (with init) ( 4)';
  ok $o->foo, 987,                           'new_hash_init (with init) ( 5)';
  ok $o->bar, 654,                           'new_hash_init (with init) ( 6)';
  ok $#args_in_init, $#args,                 'new_hash_init (with init) ( 7)';
  ok($args_in_init[$_], $args[$_],
     sprintf('new_hash_init (with init) (%2d)', $_+8))
    for 0..$#args;

  $foo_called = 0;
  $bar_called = 0;
  @args_in_init = ();
}

# ----------------------------------------------------------------------------

