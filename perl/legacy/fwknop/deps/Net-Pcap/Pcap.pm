#
# Pcap.pm
#
# An interface to the LBL pcap(3) library.  This module simply
# bootstraps the extensions defined in Pcap.xs
#
# Copyright (c) 1999-2000 Tim Potter. All rights reserved. This program is
# free# software; you can redistribute it and/or modify it under the same
# terms as Perl itself.
#
# Comments/suggestions to tpot@frungy.org
#
# $Id: Pcap.pm 209 2005-03-21 02:37:37Z mbr $
#

package Net::Pcap;

require Exporter;
require DynaLoader;

use vars qw($VERSION @ISA);

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw();

$VERSION = '0.05';

bootstrap Net::Pcap $VERSION;

1;

# autoloaded methods go after the END token (&& pod) below

__END__

=head1 NAME

B<Net::Pcap> - Interface to pcap(3) LBL packet capture library

=head1 SYNOPSIS

  use Net::Pcap;

=head1 DESCRIPTION

B<Net::Pcap> is a Perl binding to the LBL pcap(3) library, version
0.7.2.  The README for libpcap describes itself as:

  "a system-independent interface for user-level packet capture.
  libpcap provides a portable framework for low-level network
  monitoring.  Applications include network statistics collection,
  security monitoring, network debugging, etc."

=head1 FUNCTIONS

All functions defined by B<Net::Pcap> are direct mappings to the
libpcap functions.  Consult the pcap(3) documentation and source code
for more information.

Arguments that change a parameter, for example B<Net::Pcap::lookupdev()>,
are passed that parameter as a reference.  This is to retain
compatibility with previous versions of B<Net::Pcap>.

=head2 Lookup functions

=over

=item B<Net::Pcap::lookupdev(\$err);>

Returns the name of a network device that can be used with
B<Net::Pcap::open_live() function>.  On error, the $err parameter is
filled with an appropriate error message else it is undefined.

=item B<Net::Pcap::findalldevs(\$err);>

Returns a list of all network device names that can be used with
B<Net::Pcap::open_live() function>.  On error, the $err parameter is
filled with an appropriate error message else it is undefined.

=item B<Net::Pcap::lookupnet($dev, \$net, \$mask, \$err);>

Determine the network number and netmask for the device specified in
$dev.  The function returns 0 on success and sets the $net and
$mask parameters with values.  On failure it returns -1 and the
$err parameter is filled with an appropriate error message.

=head2 Packet capture functions

=over

=item B<Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err);>

Returns a packet capture descriptor for looking at packets on the
network.  The $dev parameter specifies which network interface to
capture packets from.  The $snaplen and $promisc parameters specify
the maximum number of bytes to capture from each packet, and whether
to put the interface into promiscuous mode, respectively.  The $to_ms
parameter specifies a read timeout in ms.  The packet descriptor will
be undefined if an error occurs, and the $err parameter will be set
with an appropriate error message.

=item B<Net::Pcap::loop($pcap_t, $cnt, \&callback_fn, $user_data);>

Read $cnt packets from the packet capture descriptor $pcap_t and call
the perl function &callback_fn with an argument of $user_data.  If $cnt is negative, then the function loops forever or until an error occurs.

The callback function is also passed packet header information and
packet data like so:

  sub process_pkt {
      my($user_data, $hdr, $pkt) = @_;

      ...
  }

The header information is a reference to a hash containing the
following fields.

=over

=item * len

The total length of the packet.

=item * caplen

The actual captured length of the packet data.  This corresponds to
the snapshot length parameter passed to B<Net::Pcap::open_live()>.

=item * tv_sec

Seconds value of the packet timestamp.

=item * tv_usec

Microseconds value of the packet timestamp.

=back

=item B<Net::Pcap::open_offline($filename, \$err);>

Return a packet capture descriptor to read from a previously created
"savefile".  The returned descriptor is undefined if there was an
error and in this case the $err parameter will be filled.  Savefiles
are created using the Net::Pcap::dump_* commands.

=item B<Net::Pcap::close($pcap_t);>

Close the packet capture device associated with descriptor $pcap_t.

=item B<Net::Pcap::dispatch($pcap_t, $cnt, \&callback_fn, $user_data);>

Collect $cnt packets and process them with callback function
&callback_fn.  if $cnt is -1, all packets currently buffered are
processed.  If $cnt is 0, process all packets until an error occurs. 

=item B<Net::Pcap::next($pcap_t, \%hdr);>

Return the next available packet on the interface associated with
packet descriptor $pcap_t.  Into the %hdr hash is stored the received
packet header.  If not packet is available, the return value and
header is undefined.

=item B<Net::Pcap::compile($pcap_t, \$filter_t, $filter_str, $optimize, $netmask);>

Compile the filter string contained in $filter_str and store it in
$filter_t.  A description of the filter language can be found in the
libpcap source code, or the manual page for tcpdump(8) .  The filter
is optimized the filter if the $optimize variable is true.  The
netmask of the network device must be specified in the $netmask
parameter.  The function returns 0 if the compilation was successful,
or -1 if there was a problem.

=item B<Net::Pcap::setfilter($pcap_t, $filter_t);>

Associate the compiled filter stored in $filter_t with the packet
capture descriptor $pcap_t.

=back

=head2 Savefile commands

=over

=item B<Net::Pcap::dump_open($pcap_t, $filename);>

Open a savefile for writing and return a descriptor for doing so.  If
$filename is "-" data is written to standard output.  On error, the
return value is undefined and B<Net::Pcap::geterr()> can be used to
retrieve the error text.

=item B<Net::Pcap::dump($pcap_dumper_t, \%hdr, $pkt);>

Dump the packet described by header %hdr and packet data $pkt to the
savefile associated with $pcap_dumper_t.  The packet header has the
same format as that passed to the B<Net::Pcap::loop()> callback.

=item B<Net::Pcap::dump_close($pcap_dumper_t);>

Close the savefile associated with descriptor $pcap_dumper_t.

=back

=head2 Status functions

=over

=item B<Net::Pcap::datalink($pcap_t);>

Returns the link layer type associated with the currently open device.

=item B<Net::Pcap::snapshot($pcap_t);>

Returns the snapshot length (snaplen) specified in the call to
B<Net::Pcap::open_live()>.

=item B<Net::Pcap::is_swapped($pcap_t);>

This function returns true if the endianness of the currently open
savefile is different from the endianness of the machine.

=item B<Net::Pcap::major_version($pcap_t);>

Return the major version number of the pcap library used to write the
currently open savefile.

=item B<Net::Pcap::minor_version($pcap_t);>

Return the minor version of the pcap library used to write the
currently open savefile.

=item B<Net::Pcap::stats($pcap_t, \%stats);>

Returns a hash containing information about the status of packet
capture device $pcap_t.  The hash contains the following fields.

=over

=item * B<ps_recv>

The number of packets received by the packet capture software.

=item * B<ps_drop>

The number of packets dropped by the packet capture software.

=item * B<ps_ifdrop>

The number of packets dropped by the network interface.

=back

=item B<Net::Pcap::file($pcap_t);>

Return the filehandle associated with a savefile opened with
B<Net::Pcap::open_offline()>.

=item B<Net::Pcap::fileno($pcap_t);>

Return the file number of the network device opened with
B<Net::Pcap::open_live()>.

=back

=head2 Error handling

=over

=item B<Net::Pcap::geterr($pcap_t);>

Return an error message for the last error associated with the packet
capture device $pcap_t.

=item B<Net::Pcap::strerror($errno);>

Return a string describing error number $errno.

=item B<Net::Pcap::perror($pcap_t, $prefix);>

Print the text of the last error associated with descriptor $pcap_t on
standard error, prefixed by $prefix.

=back

=head1 LIMITATIONS

The following limitations apply to this version of B<Net::Pcap>.

=over 

=item *

At present, only one callback function and user data scalar can be
current at any time as they are both stored in global variables.

=back

=head1 EXAMPLES

See the 't' directory of the B<Net::Pcap> distribution for examples
on using this module.

=head1 COPYRIGHT

Copyright (c) 1999-2000 Tim Potter. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=head1 SEE ALSO

pcap(3), tcpdump(8)

The source code for libpcap is available from B<ftp://ftp.ee.lbl.gov/libpcap.tar.Z>

=head1 AUTHOR

Tim Potter E<lt>tpot@frungy.orgE<gt>

=cut
