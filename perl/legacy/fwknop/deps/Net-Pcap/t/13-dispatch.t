#!/usr/bin/perl -w
#
# Test dispatch function
#
# $Id: 13-dispatch.t 209 2005-03-21 02:37:37Z mbr $
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

#
# Test loop on open_live interface
#

$dev = Net::Pcap::lookupdev(\$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 1, \$err);

if (!defined($pcap_t)) {
    print("Net::Pcap::open_live returned error $err\n");
    print("not ok\n");
    exit;
}

sub process_pkt {
    my($user, $hdr, $pkt) = @_;

    if (($user ne "abc") or !defined($hdr) or !defined($pkt)) {
	print("Bad args passed to callback\n");
	print("Bad user data\n"), if ($user ne "abc");
	print("Bad pkthdr\n"), if (!defined($hdr));
	print("Bad pkt data\n"), if (!defined($pkt));
	print("not ok\n");
	exit;
    }

    print("Received packet of len $hdr->{len}\n");
}

Net::Pcap::dispatch($pcap_t, 10, \&process_pkt, "abc");
Net::Pcap::close($pcap_t);

print("ok\n");
