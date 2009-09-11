#!/usr/bin/perl
use strict;
use warnings;

use Net::RawIP;
use Getopt::Long qw(GetOptions);

my $device = 'lo'; # eth0 ?
my $count  = 20;
my $port;
my @flags   = qw/URG ACK PSH RST SYN FIN/; 

GetOptions(
    "device=s" => \$device,
    "port=s"   => \$port,
) or usage();
usage() if not $port;

my $rawip  = Net::RawIP->new;
my $filter = "dst port $port";
my $packet_size = 1500;
my $pcap = $rawip->pcapinit($device, $filter, $packet_size, 30);
my @x;
loop $pcap, $count, \&callback, \@x;

sub callback {
    $rawip->bset(substr( $_[2],14));
    my @fl = $rawip->get({tcp=>
                    [qw(psh syn fin rst urg ack)]
	       });
    print "Client -> ";
    map { print "$flags[$_] "  if $fl[$_] } (0..5);
    print "\n"
}




sub usage {
    print <<"END_USAGE";
Usage: $0
        --device DEVICE     [lo|eth0|...]
        --port   PORT
END_USAGE

    exit;
}
