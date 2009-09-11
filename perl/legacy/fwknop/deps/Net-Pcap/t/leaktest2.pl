#!/usr/bin/perl -w
#
# Test for memory leaks in lookup functions
#
# $Id: leaktest2.pl 209 2005-03-21 02:37:37Z mbr $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

my($dev, $net, $mask, $err, $result);

while(1) {
    $dev = Net::Pcap::lookupdev(\$err);
    $result = Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);
}
