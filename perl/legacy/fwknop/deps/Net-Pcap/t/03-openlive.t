#!/usr/bin/perl -w
#
# Test open_live functions
#
# $Id: 03-openlive.t 209 2005-03-21 02:37:37Z mbr $
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

my($dev, $pcap_t, $err);

#
# Test open_live function
#

$dev = Net::Pcap::lookupdev(\$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

if (!defined($pcap_t)) {
    print("Net::Pcap::open_live returned error $err\n");
    print("not ok\n");
    exit;
}

print("ok\n");

#
# Test close function
#

Net::Pcap::close($pcap_t);
print("ok\n");

#
# Test open_live() with dodgy device
#

$pcap_t = Net::Pcap::open_live("beans", 1024, 1, 0, \$err);

if (defined($pcap_t)) {
    print("not ok\n");
} else {
    print("ok\n");
}
