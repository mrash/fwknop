#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package Y;
sub new { bless { foo => 'foo', bar => 'bar', arg => $_[1] }, $_[0]; }
sub foo { shift->{'foo'}; }
sub bar {
  my ($self, $new) = @_;
  defined $new and $self->{'bar'} = $new;
  $self->{'bar'};
}

package Z;

use Class::MethodMaker
  new_hash_init => 'new',
  object        => [ 'Y' => 'a' ];

package X;

use Class::MethodMaker
  object  => [
	      'Y' => 'a',
	      'Y' => [ qw / b c d / ],
	      'Y' => [
		      {
		       slot => 'e',
		       comp_mthds => [ qw / foo / ],
		      },
		      {
		       slot => 'f',
		       comp_mthds => [ qw / bar / ],
		      }
		     ],
              'Z' => 'z',
	     ];

sub new { bless {}, shift; }

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

my $o = new X;

TEST { 1 };

TEST { ref $o->a eq 'Y' };
TEST { ref $o->b eq 'Y' };

my $y = new Y;
TEST { $o->c($y); };
TEST { $o->c eq $y };
TEST { ref $o->c eq 'Y' };

TEST { ref $o->e eq 'Y' };

TEST { $o->foo eq 'foo' };
TEST { $o->bar('bar') };
TEST { $o->bar eq 'bar' };

TEST { $o->e->foo eq $o->foo };

TEST { $o->d('barney') };
my $d;
TEST { $d = $o->d };
TEST { ref $d eq 'Y' };

TEST { $d->{arg} eq 'barney' };

my $z;
TEST { $z = Z->new };
TEST { $z->a };
TEST { $o->z };

exit 0;

