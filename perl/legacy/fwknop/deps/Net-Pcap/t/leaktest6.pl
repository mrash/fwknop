#!/usr/bin/perl -w
#
# Test for memory leaks in stats() function
#
# $Id: leaktest6.pl 209 2005-03-21 02:37:37Z mbr $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

die("Must run as root!\n"), if ($UID != 0);

my($dev, $err, $pcap_t);

$dev = Net::Pcap::lookupdev(\$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

if (!defined($pcap_t)) {
    die("Net::Pcap::open_live returned error $err");
}

my $count;

sub process_pkt {
    my($user, $hdr, $pkt) = @_;
    my(%stats);

    $count++;

    Net::Pcap::stats($pcap_t, \%stats);

    print("$count\n"), if (($count % 1000) == 0);
}

Net::Pcap::loop($pcap_t, 0, \&process_pkt, "1234");
Net::Pcap::close($pcap_t);
