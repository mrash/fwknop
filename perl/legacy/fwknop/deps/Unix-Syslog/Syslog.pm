# $Id: Syslog.pm 3 2004-06-25 02:18:47Z mbr $
#
# Copyright (C) 1999,2000,2001,2002 Marcus Harnisch <marcus.harnisch@gmx.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Artistic License. A copy of the license (see
# file Artistic in this directory) must be included in the package.

package Unix::Syslog;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

@EXPORT_OK = qw(LOG_EMERG LOG_ALERT LOG_CRIT LOG_ERR LOG_WARNING LOG_NOTICE
		LOG_INFO LOG_DEBUG LOG_KERN LOG_USER LOG_MAIL LOG_DAEMON
		LOG_AUTH LOG_SYSLOG LOG_LPR LOG_NEWS LOG_UUCP LOG_CRON
		LOG_AUTHPRIV LOG_FTP LOG_LOCAL0 LOG_LOCAL1 LOG_LOCAL2
		LOG_LOCAL3 LOG_LOCAL4 LOG_LOCAL5 LOG_LOCAL6 LOG_LOCAL7
		LOG_PID LOG_CONS LOG_ODELAY LOG_NDELAY LOG_NOWAIT LOG_PERROR
		LOG_NFACILITIES LOG_FACMASK LOG_FAC LOG_MASK LOG_PRI LOG_UPTO
		LOG_MAKEPRI closelog openlog syslog setlogmask priorityname
		facilityname);

%EXPORT_TAGS = ("macros" => [qw(LOG_EMERG LOG_ALERT LOG_CRIT LOG_ERR
				LOG_WARNING LOG_NOTICE LOG_INFO LOG_DEBUG
				LOG_KERN LOG_USER LOG_MAIL LOG_DAEMON LOG_AUTH
				LOG_SYSLOG LOG_LPR LOG_NEWS LOG_UUCP LOG_CRON
				LOG_AUTHPRIV LOG_FTP LOG_LOCAL0 LOG_LOCAL1
				LOG_LOCAL2 LOG_LOCAL3 LOG_LOCAL4 LOG_LOCAL5
				LOG_LOCAL6 LOG_LOCAL7 LOG_PID LOG_CONS
				LOG_ODELAY LOG_NDELAY LOG_NOWAIT LOG_PERROR
				LOG_NFACILITIES LOG_FACMASK LOG_FAC LOG_MASK
				LOG_PRI LOG_UPTO LOG_MAKEPRI)],
		"subs"  => [qw(closelog openlog syslog setlogmask priorityname
			       facilityname)]);

$VERSION = '0.100';

bootstrap Unix::Syslog $VERSION;

# Preloaded methods go here.

sub syslog($$@) {
    my $priority = shift;
    my $format   = shift;

    $format =~ s/((?:[^%]|^)(?:%%)*)%m/$1$!/g;

    my $msg =  sprintf($format,@_);

    _isyslog($priority, $msg);
}

# openlog, closelog and setlogmask don't need a wrapper

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Unix::Syslog - Perl interface to the UNIX syslog(3) calls

=head1 SYNOPSIS

 use Unix::Syslog qw(:macros);  # Syslog macros
 use Unix::Syslog qw(:subs);    # Syslog functions

 openlog $ident, $option, $facility;
 syslog $priority, $format, @formatargs;
 closelog;
 $oldmask = setlogmask $mask_priority;

=head1 DESCRIPTION

This module provides an interface to the system logger B<syslogd>(8) via
Perl's XSUBs. The implementation attempts to resemble the native
libc-functions of your system, so that anyone being familiar with
F<syslog.h> should be able to use this module right away.

In contrary to Sys::Syslog(3), this modules does not open a network
connection to send the messages. This can help you to avoid opening
security holes in your computer (see L<"FAQ">).

The subs imported by the tag C<macros> are simply wrappers around the
most important C<#defines> in your system's C header file
F<syslog.h>. The macros return integer values that are used to specify
options, facilities and priorities in a more or less portable
way. They also provide general information about your local syslog
mechanism. Check syslog(3) and your local F<syslog.h> for information
about the macros, options and facilities available on your system.

The following functions are provided:

=over

=item openlog $ident, $option, $facility

opens a connection to the system logger.  I<$ident> is an identifier
string that B<syslogd>(8) prints into every message. It usually equals
the process name. I<$option> is an integer value that is the result of
ORed options. I<$facility> is an integer value that specifies the part
of the system the message should be associated with (e.g. kernel
message, mail subsystem).

=item syslog $priority, $format, @formatargs

Generates a log message and passes it to the system logger. If
C<syslog()> is called without calling C<openlog()> first, probably
system dependent default values will be used as arguments for an
implicit call to C<openlog()>.

I<$priority> is an integer value that specifies the priority of the
message. Alternatively I<$priority> can be the ORed value of a
priority and a facility. In that case a previously selected facility
will be overridden.

In the case that C<syslog()> is called without calling C<openlog()>
first and I<priority> does not specify both a priority I<and> a
facility, a default facility will be used. This behaviour is most
likely system dependent and the user should not rely on any particular
value in that case.

I<$format> is a format string in the style of printf(3). Additionally
to the usual printf directives C<%m> can be specified in the
string. It will be replaced implicitly by the contents of the Perl
variable C<$!> (C<$ERRNO>). I<@formatargs> is a list of values that
the format directives will be replaced with subsequently.

=item closelog

closes the connection to the system logger.

=item setlogmask $mask_priority

sets the priority mask and returns the old mask. Logging is enabled
for the priorities indicated by the bits in the mask that are set and
is disabled where the bits are not set. Macros are provided to specify
valid and portable arguments to C<setlogmask()>. Usually the default
log mask allows all messages to be logged.

=item priorityname $priority

returns a string containing the name of I<$priority> as string. If
this functionality has not been enabled at installation, the function
returns I<undef>.

=item facilityname $facility

returns a string containing the name of I<$facility> as string. If
this functionality has not been enabled at installation, the function
returns I<undef>.

=back

B<NOTE>: The behaviour of this module is system dependent. It is highly
recommended to consult your system manual for available macros and the
behaviour of the provided functions.

=head1 RETURN VALUES

The functions openlog(), syslog() and closelog() return the undefined
value. The function setlogmask returns the previous mask value.

=head1 EXAMPLES

Open a channel to syslogd specifying an identifier (usually the
process name) some options and the facility:
  C<openlog "test.pl", LOG_PID | LOG_PERROR, LOG_LOCAL7;>

Generate log message of specified priority using a printf-type formatted
string:
  C<syslog LOG_INFO, "This is message number %d", 42;>

Set log priority mask to block all messages but those of priority
C<LOG_DEBUG>:
  C<$oldmask = setlogmask(LOG_MASK(LOG_DEBUG))>

Set log priority mask to block all messages with a higher priority than
C<LOG_ERR>:
  C<$oldmask = setlogmask(LOG_UPTO(LOG_ERR))>

Close channel to syslogd:
  C<closelog;>

=head1 FAQ

=over

=item 1.

What is the benefit of using this module instead of Sys::Syslog?

Sys::Syslog always opens a network connection to the syslog
service. At least on Linux systems this may lead to some trouble,
because

=over 4

=item *

Linux syslogd (from package sysklogd) does not listen to the network
by default. Most people working on stand-alone machines (including me)
didn't see any reason why to enable this option. Others didn't enable
it for security reasons.

OS-independent, some sysadmins may run a firewall on their network
that blocks connections to port 514/udp.

=item *

By default Linux syslogd doesn't forward messages which have already
already received from the network to other log hosts. There are
reasons not to enable this option unless it is really
necessary. Looping messages resulting from a misconfiguration may
break down your (log-)system.

=back

Peter Stamfest <peter.stamfest@eunet.at> pointed out some other
advantages of Unix::Syslog, I didn't came across my self.

=over

=item *

LOG_PERROR works.

=item *

works with perl -Tw without warnings and problems due to tainted data
as it is the case for Sys::Syslog in some special
applications. [Especially when running a script as root]

=back

=item 2.

Well, is there any reason to use Sys::Syslog any longer?

Yes! In contrary to Unix::Syslog, Sys::Syslog works even if you don't
have a syslog daemon running on your system as long as you are
connected to a log host via a network and have access to the
F<syslog.h> header file of your log host to generate the initial files
for Sys::Syslog (see Sys::Syslog(3) for details). Unix::Syslog only logs
to your local syslog daemon which in turn may be configured to
distribute the message over the network.

=item 3.

Are calls to the functions provided by Unix::Syslog compatible to those
of Sys::Syslog?

Currently not. Sys::Syslog requires strings to specify many of the
arguments to the functions, while Unix::Syslog uses numeric constants
accessed via macros as defined in F<syslog.h>. Although the strings
used by Sys::Syslog are also defined in F<syslog.h>, it seems that most
people got used to the numeric arguments. I will implement the string
based calls if there are enough people (I<$min_people> > 10**40)
complaining about the lack of compatibility.

=back

=head1 SEE ALSO

syslog(3), Sys::Syslog(3), syslogd(8), perl(1)

=head1 AUTHOR

Marcus Harnisch <marcus.harnisch@gmx.net>

=cut
