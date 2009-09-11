#!/usr/bin/perl -w
#
# Test misc functions
#
# $Id: 11-misc.t 209 2005-03-21 02:37:37Z mbr $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

print("1..3\n");

# Must run as root

if ($UID != 0 && $^O !~ /cygwin/i) {
    print("not ok\n");
    exit;
}

my($dev, $pcap_t, $err, $slen);

#
# Test snapshot
#

$dev = Net::Pcap::lookupdev(\$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

if (!defined($pcap_t)) {
    print("Net::Pcap::open_live returned error $err\n");
    print("not ok\n");
    exit;
}

$slen = Net::Pcap::snapshot($pcap_t);

if ($slen != 1024) {
    print("bad snapshot len $slen\n");
    print("not ok\n");
} else {
    print("ok\n");
}

Net::Pcap::close($pcap_t);

$pcap_t = Net::Pcap::open_live($dev, 2048, 1, 0, \$err);

if (!defined($pcap_t)) {
    print("Net::Pcap::open_live returned error $err");
    print("not ok\n");
    exit;
}

$slen = Net::Pcap::snapshot($pcap_t);

if ($slen != 2048) {
    print("bad snapshot len $slen\n");
    print("not ok\n");
} else {
    print("ok\n");
}

#
# Test datalink function
#

my $dlt = Net::Pcap::datalink($pcap_t);
print("Datalink is $dlt\n");


if (($dlt < 0) or !(defined($dlt))) {
    print("bad datalink type\n");
    print("not ok\n");
} else {
    print("ok\n");
}

Net::Pcap::close($pcap_t);
