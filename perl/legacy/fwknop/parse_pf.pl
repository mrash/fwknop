#!/usr/bin/perl -w

use strict;

open F, "< pf.os" or die;
my @lines = <F>;
close F;

#16384:64:0:60:M512,N,W%2,N,N,T:         AIX:4.3:3:AIX 4.3.3-5.2
#S3:64:1:60:M*,S,T,N,W0:         Linux:2.4:18-21:Linux 2.4.18 and newer

my %os;

for my $line (@lines) {
    next unless $line =~ /\S/;
    next if $line =~ /^\s*#/;
    chomp $line;

#    if ($line =~ /^\s*(\S+?:\S+?:\S+?:\S+?):\S+\s+(.*)/) {
    if ($line =~ /^\s*(\S+?:\S+?:\S+?:\S+?:\S+:)\s+(.*)/) {
        $os{$1}{$2} = '';
    }
}

for my $fp (sort keys %os) {
    print $fp, "\n";
    for my $os (sort keys %{$os{$fp}}) {
        print "    $os\n";
    }
    print "\n";
}

exit 0;
