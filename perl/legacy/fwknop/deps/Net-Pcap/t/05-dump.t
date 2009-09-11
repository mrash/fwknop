#!/usr/bin/perl -w
#
# Test loop function
#
# $Id: 05-dump.t 209 2005-03-21 02:37:37Z mbr $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

print("1..1\n");

my($dev, $pcap_t, $pcap_dumper_t, $err);
my $dumpfile = "/tmp/Net-Pcap-dump.$$";

# Must run as root

if ($UID != 0 && $^O !~ /cygwin/i) {
    print("not ok\n");
    exit;
}

#
# Test loop on open_live interface
#

$dev = Net::Pcap::lookupdev(\$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

if (!defined($pcap_t)) {
    print("Net::Pcap::open_live returned error $err\n");
    print("not ok\n");
    exit;
}

$pcap_dumper_t = Net::Pcap::dump_open($pcap_t, $dumpfile);

if (!defined($pcap_dumper_t)) {
    print("Net::Pcap::dump_open failed: ", Net::Pcap::geterr($pcap_t), "\n");
    print("not ok\n");
    exit;
}

my($count) = 0;

sub process_pkt {
    my($user, $hdr, $pkt) = @_;

    if (($user ne "xyz") or !defined($hdr) or !defined($pkt)) {
	print("Bad args passed to callback\n");
	print("Bad user data\n"), if ($user ne "xyz");
	print("Bad pkthdr\n"), if (!defined($hdr));
	print("Bad pkt data\n"), if (!defined($pkt));
	print("not ok\n");
	exit;
    }

    Net::Pcap::dump($pcap_dumper_t, $hdr, $pkt);

    $count++;
}

Net::Pcap::loop($pcap_t, 10, \&process_pkt, "xyz");
Net::Pcap::close($pcap_t);

Net::Pcap::dump_close($pcap_dumper_t);

if (!-f $dumpfile) {
    print("No save file created\n");
    print("not ok\n");
} else {
    print("ok\n");
}

END {
    unlink($dumpfile);
}
