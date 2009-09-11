#!/usr/bin/perl -w
#
# Test stats
#
# $Id: 07-stats.t 209 2005-03-21 02:37:37Z mbr $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

print("1..1\n");

# Must run as root

if ($UID != 0 && $^O !~ /cygwin/i) {
    print("not ok\n");
    exit;
}

my($dev, $pcap_t, $err);

$dev = Net::Pcap::lookupdev(\$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

if (!defined($pcap_t)) {
    print("Net::Pcap::open_live returned error $err\n");
    print("not ok\n");
    exit;
}

my $count = 0;

sub process_pkt
{
    my($user, $hdr, $pkt) = @_;
    my %stats;
    
    print("In process_pkt:\n");

    Net::Pcap::stats($pcap_t, \%stats);

    $count++;

    if ($count != $stats{ps_recv}) {
	print("Bad statistics\n");
	print("not ok\n");
	exit;
    }

    print("Received $stats{ps_recv}, dropped $stats{ps_drop}, ", 
	  "interface dropped $stats{ps_ifdrop}\n");
}

Net::Pcap::loop($pcap_t, 10, \&process_pkt, 0);
Net::Pcap::close($pcap_t);

print("ok\n");
