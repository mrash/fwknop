#!/usr/bin/perl -w
#
# Test lookup functions
#
# $Id: 02-lookup.t 209 2005-03-21 02:37:37Z mbr $
#

use strict;

use ExtUtils::testlib;
use Net::Pcap;

print("1..2\n");

my($dev, $net, $mask, $err);

#
# Test lookupdev() function
#

$dev = Net::Pcap::lookupdev(\$err);

if ($dev eq "") {
    print("not ok\n");
} else {
    print("ok\n");
}

if ($dev eq "") {
    print("Net::Pcap::lookupdev returned error $err\n");
    print("not ok\n");
    exit;
} else {
    print("Net::Pcap::lookupdev returned device $dev\n");
}

#
# Test lookupnet() function
#

# From test.pl, Net-Pcap-0.01.tar.gz

sub dotquad {
    my($na, $nb, $nc, $nd);
    my ( $net ) = @_ ;
    $na=$net >> 24 & 255 ;
    $nb=$net >> 16 & 255 ;
    $nc=$net >>  8 & 255 ;
    $nd=$net & 255 ;
    return ( "$na.$nb.$nc.$nd") ;
}

my($result);

$result = Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);

if ($result == -1) {
    print("not ok\n");
    print("Net::Pcap::lookupnet returned error $err\n");
    exit;	  
} else {
    print("Net::Pcap::lookupnet returned net ", dotquad($net),
	  " and mask ", dotquad($mask), "\n");
}

if (($net == 0) or ($mask == 0)) {
    print("not ok\n");
} else {
    print("ok\n");
}
