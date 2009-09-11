#!/usr/bin/perl -w
#
# Test loop function
#
# $Id: 10-fileno.t 209 2005-03-21 02:37:37Z mbr $
#

use strict;
use English;

use ExtUtils::testlib;
use Net::Pcap;

print("1..2\n");

my($dev, $pcap_t, $pcap_dumper_t, $err);
my $dumpfile = "/tmp/Net-Pcap-dump.$$";

# Must run as root

if ($UID != 0 && $^O !~ /cygwin/i) {
    print("not ok\n");
    exit;
}

#
# Test file and fileno on offline interface
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

$pcap_t = Net::Pcap::open_offline($dumpfile, \$err);

if (!defined($pcap_t)) {
    print("Net::Pcap::open_offline returned error $err\n");
    print("not ok\n");
    exit;
}

#
# Test file and fileno on live connection
#

my($fh, $fileno);

$dev = Net::Pcap::lookupdev(\$err);
$pcap_t = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

if (!defined($pcap_t)) {
    die("Net::Pcap::open_live returned error $err");
}

$fh = Net::Pcap::file($pcap_t);
$fileno = Net::Pcap::fileno($pcap_t);

if (defined($fh)) {
    print("bad file handle returned by Net::Pcap::file\n");
    print("not ok\n");
} else {
    print("ok\n");
}

if ($fileno < 0) {
    print("Bad fileno returned by Net::Pcap::fileno\n");
    print("not ok\n");
} else {
    print("File descriptor returned is $fileno\n");
    print("ok\n");
}

Net::Pcap::close($pcap_t);

END {
    unlink($dumpfile);
}
