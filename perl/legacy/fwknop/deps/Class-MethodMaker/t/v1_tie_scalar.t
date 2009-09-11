#!/usr/local/bin/perl
use lib qw ( ./t );
use test_v1;

package Y;

use Carp;
use strict;

require Tie::Scalar ;

sub TIESCALAR
  {
    my $type = shift;
    my %args = @_ ;
    my $self={} ;
    if (defined $args{enum})
      {
        # store all enum values in a hash. This way, checking
        # whether a value is present in the enum set is easier
        map {$self->{enum}{$_} =  1;} @{$args{enum}} ;
      }
    else
      {
        croak ref($self)," error: no enum values defined when calling init";
      }

    $self->{default} = $args{default};
    bless $self,$type;
  }

sub STORE
  {
    my ($self,$value) = @_ ;
    croak "cannot set ",ref($self)," item to $value. Expected ",
      join(' ',keys %{$self->{enum}})
        unless defined $self->{enum}{$value} ;
    # we may want to check other rules here ... TBD
    $self->{value} = $value ;
    return $value;
  }


sub FETCH
  {
    my $self = shift ;
    return defined $self->{value} ? $self->{value} : $self->{default}  ;
  }

package X ;
use ExtUtils::testlib;

use Class::MethodMaker
  tie_scalar =>
  [
   a => ['Y',
         enum =>    [qw/A B C/],
         default => 'B' ],
  ],
  new => 'new';

package main;

Class::MethodMaker->VERSION eq '2.08' || Class::MethodMaker->VERSION >= 2.00
  or die "Wrong C::MM: ", Class::MethodMaker->VERSION, "\n";

use ExtUtils::testlib;

my $o = new X;

TEST { 1 };
TEST {$o->a eq 'B'} ;
TEST {$o->a('A') eq 'A'} ;
TEST {$o->a eq 'A'} ;

exit 0;

