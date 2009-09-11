#!/usr/bin/perl -w
#
# Test open_live functions
#
# $Id: 09-error.t 209 2005-03-21 02:37:37Z mbr $
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

my($dev, $pcap_t, $err, $net, $mask);
my($result, $filter);

$dev = Net::Pcap::lookupdev(\$err);
$result = Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

if (!defined($pcap_t)) {
    print("Net::Pcap::open_live returned error $err");
    print("not ok\n");
    exit;
}

$result = Net::Pcap::compile($pcap_t, \$filter, "beans and ham", 0, $mask);

if ($result == 0) {
    print("Call to Net::Pcap::compile actually worked!");
    print("not ok\n");
    exit;
}

my($geterr, $strerror);

$geterr = Net::Pcap::geterr($pcap_t);
($geterr eq "") ? print("not ok\n") : print("ok\n");

$strerror = Net::Pcap::strerror(1);
($strerror eq "") ? print("not ok\n") : print("ok\n");

# This test, if enabled, mucks up the test harness script 

#Net::Pcap::perror($pcap_t, "$0 test error");
