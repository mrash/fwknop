#!/usr/bin/perl -w
#
# Test open_live functions
#
# $Id: 08-filter.t 209 2005-03-21 02:37:37Z mbr $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

print("1..2\n");

# Must run as root

if ($UID != 0 && $^O !~ /cygwin/i) {
    print("not ok\n");
    exit;
}

my($dev, $pcap_t, $err, $result, $net, $mask, $filter);

#
# Test filter compile function (& geterr incidentally)
#

$dev = Net::Pcap::lookupdev(\$err);
$result = Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

if (!defined($pcap_t)) {
    print("Net::Pcap::open_live returned error $err\n");
    print("\n");
    exit;
}

$result = Net::Pcap::compile($pcap_t, \$filter, "tcp", 0, $mask);

if ($result == -1) {
    print("Net::Pcap::compile returned ", Net::Pcap::geterr($pcap_t), "\n");
    print("not ok\n");
} else {
    print("ok\n");
}

#
# Test setfilter function
#

$result = Net::Pcap::setfilter($pcap_t, $filter);

if ($result == -1) {
    print(Net::Pcap::geterr($pcap_t), "\n");
    print("not ok\n");
} else {
    print("ok\n");
}

Net::Pcap::close($pcap_t);
