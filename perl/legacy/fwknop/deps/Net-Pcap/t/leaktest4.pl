#!/usr/bin/perl -w
#
# Test for memory leaks in dump() function
#
# $Id: leaktest4.pl 209 2005-03-21 02:37:37Z mbr $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

die("Must run as root!\n"), if ($UID != 0);

my($dev, $err, $pcap_t, $pcap_dumper_t);

$dev = Net::Pcap::lookupdev(\$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);
$pcap_dumper_t = Net::Pcap::dump_open($pcap_t, "/dev/null");

if (!defined($pcap_t)) {
    die("Net::Pcap::open_live returned error $err");
}

my $count;

sub process_pkt {
    my($user, $hdr, $pkt) = @_;

    $count++;

    Net::Pcap::dump($pcap_dumper_t, $hdr, $pkt);
    print("$count\n"), if (($count % 1000) == 0);
}

Net::Pcap::loop($pcap_t, 0, \&process_pkt, "1234");

Net::Pcap::dump_close($pcap_dumper_t);
Net::Pcap::close($pcap_t);
