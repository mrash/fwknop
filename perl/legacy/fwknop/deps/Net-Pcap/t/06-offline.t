#!/usr/bin/perl -w
#
# Test open_offline
#
# $Id: 06-offline.t 209 2005-03-21 02:37:37Z mbr $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

print("1..4\n");

my($pcap_t, $err);
my $dumpfile = "/tmp/Net-Pcap-dump.$$";

# Must run as root

if ($UID != 0 && $^O !~ /cygwin/i) {
    print("not ok\n");
    exit;
}

#
# Test open_offline of bad file (not created yet)
#

$pcap_t = Net::Pcap::open_offline($dumpfile, \$err);

if (defined($pcap_t)) {
    print("Net::Pcap::open_offline worked for dummy file\n");
    print("not ok\n");
} else {
    print("ok\n");
}

#
# Test open_offline of good file.  Need to create it first.
#

my($dev, $pcap_dumper_t);

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

$pcap_t = Net::Pcap::open_offline($dumpfile, \$err);

if (!defined($pcap_t)) {
    print("Net::Pcap::open_offline failed: $err\n");
    print("not ok\n");
    exit;
}

my($major, $minor, $swapped);

$major = Net::Pcap::major_version($pcap_t);
$minor = Net::Pcap::minor_version($pcap_t);
$swapped = Net::Pcap::is_swapped($pcap_t);

print("File saved with libpcap version $major.$minor, swap is $swapped\n");

if ($major == 0) {
    print("suspicious libpcap major version\n");
    print("not ok\n");
} else {
    print("ok\n");
}

my $count = 0;

sub process_pkt2 {
    my($user, $hdr, $pkt) = @_;

    if (($user ne "123") or !defined($hdr) or !defined($pkt)) {
	print("Bad args passed to callback2\n");
	print("Bad user data\n"), if ($user ne "123");
	print("Bad pkthdr\n"), if (!defined($hdr));
	print("Bad pkt data\n"), if (!defined($pkt));
	print("not ok\n");
	exit;
    }

    print("Received packet of len $hdr->{len}\n");
    $count++;
}

Net::Pcap::loop($pcap_t, 10, \&process_pkt2, "123");
Net::Pcap::close($pcap_t);

if ($count != 10) {
    print("not ok\n");
} else {
    print("ok\n");
}

END {
    unlink($dumpfile);
}
