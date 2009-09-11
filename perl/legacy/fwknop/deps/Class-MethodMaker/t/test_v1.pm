package test_v1;

#
# $Id: test_v1.pm 386 2005-12-11 22:38:17Z mbr $
#

# COPYRIGHT NOTICE
#
# Copyright 1996 Organic Online, Inc.  Title, ownership rights, and
# intellectual property rights in and to this software remain with
# Organic Online, Inc.  Organic Online, Inc. hereby reserves all rights
# in and to this software.  This software may not be copied, modified,
# or used without a license from Organic Online, Inc.  This software is
# protected by international copyright laws and treaties, and may be
# protected by other law.  Violation of copyright laws may result in
# civil liability and criminal penalties.

use strict;

use Exporter;
use vars qw ( @ISA @EXPORT );
@ISA = qw ( Exporter );
@EXPORT = qw ( TEST COUNT_TESTS PRINT_TEST_HEADER find_test );

use FindBin                  1.42 qw( $Bin );
use File::Spec::Functions qw( catdir catfile rel2abs updir );
use lib $Bin, catdir $Bin, updir, 'lib';

my $COUNTER = 0;

$| = 1;
print "1..", &COUNT_TESTS(), "\n" unless $0 =~ /^-e/;

sub TEST (&) {
  my ($code) = @_;
  $COUNTER++;
  &$code or print "not ";
  print "ok $COUNTER\n";
}

sub COUNT_TESTS {
  my ($file) = @_;
  $file ||= $0;
  my $c = 0;
  open(IN, $file) or die "Can't open $file: $!";
  while (<IN>) {
    /^\s*#/ and next;
    $c += s/(TEST\s{)/$1/g;
  }
  $c;
}

sub find_test ($@) {
  my ($file, @numbers) = @_;
  open(T, $file) or die "Can't open $file: $!";
  local $/ = undef;
  my $content = <T>;
  my $c = 0;
  my %tests = map { ++$c, $_ } $content =~ /\nTEST\s+{.*?};/gs;
  @numbers or @numbers = (1 .. $c);
  foreach (@numbers) {
    print "#$_: $tests{$_}\n";
  }
}

1;

__END__
