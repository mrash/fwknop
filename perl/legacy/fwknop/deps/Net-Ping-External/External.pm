package Net::Ping::External;

# Author:   Colin McMillen (colinm@cpan.org)
# See also the CREDITS section in the POD below.
#
# Copyright (c) 2003 Colin McMillen.  All rights reserved.  This
# program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use Carp;
use Socket qw(inet_ntoa);
require Exporter;

$VERSION = "0.11";
@ISA = qw(Exporter);
@EXPORT = qw();
@EXPORT_OK = qw(ping);

sub ping {
  # Set up defaults & override defaults with parameters sent.
  my %args = (count => 1, size => 56, @_);

  # "host" and "hostname" are synonyms.
  $args{host} = $args{hostname} if defined $args{hostname};

  # If we have an "ip" argument, convert it to a hostname and use that.
  $args{host} = inet_ntoa($args{ip}) if defined $args{ip};

  # croak() if no hostname was provided.
  croak("You must provide a hostname") unless defined $args{host};
  $args{timeout} = 5 unless defined $args{timeout} && $args{timeout} > 0;

  my %dispatch = 
    (linux    => \&_ping_linux,
     mswin32  => \&_ping_win32,
     cygwin   => \&_ping_win32,
     solaris  => \&_ping_solaris,
     bsdos    => \&_ping_bsdos,
     beos     => \&_ping_beos,
     hpux     => \&_ping_hpux,
     dec_osf  => \&_ping_dec_osf,
     bsd      => \&_ping_bsd,
     darwin   => \&_ping_darwin,
     openbsd  => \&_ping_unix,
     freebsd  => \&_ping_freebsd,
     next     => \&_ping_next,
     unicosmk => \&_ping_unicosmk,
     netbsd   => \&_ping_unix,
     irix     => \&_ping_unix,
     aix      => \&_ping_aix,
    );

  my $subref = $dispatch{lc $^O};

  croak("External ping not supported on your system") unless $subref;

  return $subref->(%args);
}

# Win32 is the only system so far for which we actually need to parse the
# results of the system ping command.
sub _ping_win32 {
  my %args = @_;
  $args{timeout} *= 1000;    # Win32 ping timeout is specified in milliseconds
  my $command = "ping -l $args{size} -n $args{count} -w $args{timeout} $args{host}";
  print "$command\n" if $DEBUG;
  my $result = `$command`;
  return 1 if $result =~ /time.*ms/;
  return 0;
}

# Generic subroutine to handle pinging using the system() function. Generally,
# UNIX-like systems return 0 on a successful ping and something else on
# failure. If the return value of running $command is equal to the value
# specified as $success, the ping succeeds. Otherwise, it fails.
sub _ping_system {
  my ($command,   # The ping command to run
      $success,   # What value the system ping command returns on success
     ) = @_;
  my $devnull = "/dev/null";
  $command .= " 1>$devnull 2>$devnull";
  my $exit_status = system($command) >> 8;
  return 1 if $exit_status == $success;
  return 0;
}

# Below are all the systems on which _ping_system() has been tested
# and found OK.

# Mac OS X 10.2 ping does not handle -w timeout now does it return a
# status code if it fails to ping (unless it cannot resolve the domain 
# name)
# Thanks to Peter N. Lewis for this one.
sub _ping_darwin {
   my %args = @_;
   my $command = "ping -s $args{size} -c $args{count} $args{host}";
   my $devnull = "/dev/null";
   $command .= " 2>$devnull";
   print "$command\n" if $DEBUG;
   my $result = `$command`;
   return 1 if $result =~ /(\d+) packets received/ && $1 > 0;
   return 0;
}

# Assumed OK for DEC OSF
sub _ping_dec_osf {
  my %args = @_;
  my $command = "ping -c $args{count} -s $args{size} -q -u $args{host}";
  return _ping_system($command, 0);
}

# Assumed OK for unicosmk
sub _ping_unicosmk {
  my %args = @_;
  my $command = "ping -s $args{size} -c $args{count} $args{host}";
  return _ping_system($command, 0);
}

# NeXTStep 3.3/sparc
sub _ping_next {
  my %args = @_;
  my $command = "ping $args{host} $args{size} $args{count}";
  return _ping_system($command, 0);
}

# Assumed OK for HP-UX.
sub _ping_hpux {
  my %args = @_;
  my $command = "ping $args{host} $args{size} $args{count}";
  return _ping_system($command, 0);
}

# Assumed OK for BSD/OS 4.
sub _ping_bsdos {
  my %args = @_;
  my $command = "ping -c $args{count} -s $args{size} $args{host}";
  return _ping_system($command, 0);
}

# Assumed OK for BeOS.
sub _ping_beos {
  my %args = @_;
  my $command = "ping -c $args{count} -s $args{size} $args{host}";
  return _ping_system($command, 0);
}

# Assumed OK for AIX
sub _ping_aix {
  my %args = @_;
  my $command = "ping -c $args{count} -s $args{size} -q $args{host}";
  return _ping_system($command, 0);
}

# OpenBSD 2.7 OK, IRIX 6.5 OK
# Assumed OK for NetBSD & FreeBSD, but needs testing
sub _ping_unix {
  my %args = @_;
  my $command = "ping -s $args{size} -c $args{count} -w $args{timeout} $args{host}";
  return _ping_system($command, 0);
}

# Assumed OK for FreeBSD 3.4
# -s size option supported -- superuser only... fixme
sub _ping_bsd {
  my %args = @_;
  my $command = "ping -c $args{count} -q $args{hostname}";
  return _ping_system($command, 0);
}

# Debian 2.2 OK, RedHat 6.2 OK
# -s size option available to superuser... FIXME?
sub _ping_linux {
  my %args = @_;
  my $command = "ping -c $args{count} $args{host}";
  return _ping_system($command, 0);
}

# Solaris 2.6, 2.7 OK
sub _ping_solaris {
  my %args = @_;
  my $command = "ping -s $args{host} $args{size} $args{timeout}";
  return _ping_system($command, 0);
}

# FreeBSD. Tested OK for Freebsd 4.3
# -s size option supported -- superuser only... FIXME?
# -w timeout option for BSD replaced by -t
sub _ping_freebsd {
    my %args = @_;
    my $command = "ping -c $args{count} -t $args{timeout} $args{host}";
    return _ping_system($command, 0);
}

1;

__END__

=head1 NAME

Net::Ping::External - Cross-platform interface to ICMP "ping" utilities

=head1 SYNOPSIS

In general:

  use Net::Ping::External qw(ping);
  ping(%options);

Some examples:

  use Net::Ping::External qw(ping);

  # Ping a single host
  my $alive = ping(host => "127.0.0.1");
  print "127.0.0.1 is online" if $alive;

  # Or a list of hosts
  my @hosts = qw(127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4);
  my $num_alive = 0;
  foreach (@hosts) {
    $alive = ping(hostname => $_, timeout => 5);
    print "$_ is alive!\n" if $alive;
    $num_alive++;
  }
  print "$num_alive hosts are alive.\n";

  # Using all the fancy options:
  ping(hostname => "127.0.0.1", count => 5, size => 1024, timeout => 3);

=head1 DESCRIPTION

Net::Ping::External is a module which interfaces with the "ping" command
on many systems. It presently provides a single function, C<ping()>, that
takes in a hostname and (optionally) a timeout and returns true if the
host is alive, and false otherwise. Unless you have the ability (and
willingness) to run your scripts as the superuser on your system, this
module will probably provide more accurate results than Net::Ping will.

Why?

=over 4

=item *

ICMP ping is the most reliable way to tell whether a remote host is alive.

=item *

However, Net::Ping cannot use an ICMP ping unless you are running your
script with privileged (AKA "root") access.

=item *

The system's "ping" command uses ICMP and does not usually require
privileged access.

=item *

While it is relatively trivial to write a Perl script that parses the
output of the "ping" command on a given system, the aim of this module
is to encapsulate this functionality and provide a single interface for
it that works on many systems.

=back

=head2 ping() OPTIONS

This module is still "alpha"; it is expected that more options to the C<ping()>
function will be added soon.

=over 4

=item * C<host, hostname>

The hostname (or dotted-quad IP address) of the remote host you are trying
to ping. You must specify either the "hostname" option or the "ip" option.

"host" and "hostname" are synonymous.

=item * C<ip>

A packed bit-string representing the 4-byte packed IP address (as
returned by C<Socket.pm>'s C<inet_aton()> function) of the host that you
would like to ping.

=item * C<timeout>

The maximum amount of time, in seconds, that C<ping()> will wait for a response.
If the remote system does not respond before the timeout has elapsed, C<ping()>
will return false.

Default value: 5.

=item * C<count>

The number of ICMP ping packets to send to the remote host. Eventually,
Net::Ping::External will return the number of packets that were acknowledged
by the remote host; for now, however, C<ping()> still returns just true or false.

Default value: 1.

=item * C<size>

Specifies the number of data bytes to be sent.  The default is
56, which translates into 64 ICMP data bytes when combined with
the 8 bytes of ICMP header data.

Default value: 56.

=back

=head2 SUPPORTED PLATFORMS

Support currently exists for interfacing with the standard ping
utilities on the following systems. Please note that the path to the `ping'
should be somewhere in your PATH environment variable (or your system's
closest equivalent thereof.) Otherwise, Net::Ping::External will be unable
to locate your system's `ping' command.

=over 4

=item * Win32

Tested OK on Win98. It should work on other Windows systems as well.

=item * Linux

Tested OK on Debian 2.2 and Redhat 6.2. It appears that different versions
of Linux use different versions of ping, which support different options.
Not sure how I'm going to resolve this yet; for now, all the options but
C<count> are disabled.

=item * BSD

Tested OK on OpenBSD 2.7. Needs testing for FreeBSD, NetBSD, and BSDi.

=item * Solaris

Tested OK on Solaris 2.6 and 2.7.

=item * IRIX

Tested OK on IRIX 6.5.

=item * AIX, DEC OSF, UNICOSMK, NeXTStep, HP-UX, BSD/OS (BSDi), BeOS

Support for these systems is integrated into this module but none have been
tested yet. If you have successful or unsuccessful test results for any of
these systems, please send them to me. On some of these systems, some of the
arguments may not be supported. If you'd like to see better support on your
system, please e-mail me.

=back

More systems will be added as soon as any users request them. If your
system is not currently supported, e-mail me; adding support to your
system is probably trivial.


=head1 BUGS

This module should be considered alpha. Bugs may exist. Although no
specific bugs are known at this time, the module could use testing
on a greater variety of systems.

See the warning below.

=head1 WARNING

This module calls whatever "ping" program it first finds in your PATH
environment variable. If your PATH contains a trojan "ping" program,
this module will call that program. This involves a small amount of
risk, but no more than simply typing "ping" at a system prompt.

Beware Greeks bearing gifts.

=head1 AUTHOR

Colin McMillen (colinm@cpan.org)

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 CREDITS

Dan Moore contributed command-line options and code for NeXT, BeOS,
HP-UX, and BSD/OS.

Jarkko Hietaniemi contributed a huge list of command-line options and results
for the `ping' command on 9 different systems.

Randy Moore contributed several patches for Win32 support.

Marc-Andre Dumas contributed a patch for FreeBSD support.

Jonathan Stowe fixed a bug in 0.09 that prevented the module from
running on some systems.

Numerous people sent in a patch to fix a bug in 0.10 that broke ping on Windown systems.

Peter N. Lewis contributed a patch that works correctly on Mac OS X
10.2 (and hopefully other versions as well).

=head1 SEE ALSO

Net::Ping

=cut



