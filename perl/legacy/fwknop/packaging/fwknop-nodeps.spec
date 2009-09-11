%define name fwknop
%define version 1.9.12
%define release 1
%define fwknoplogdir /var/log/fwknop
%define fwknoprundir /var/run/fwknop

Summary: Fwknop implements Single Packet Authorization (SPA) for iptables and ipfw
Name: %name
Version: %version
Release: %release
License: GPL
Group: System/Servers
Url: http://www.cipherdyne.org/fwknop/
Source: %name-%version.tar.gz
BuildRoot: %_tmppath/%{name}-buildroot
#Prereq: rpm-helper

%description
fwknop implements an authorization scheme known as Single Packet
Authorization (SPA) that requires only a single encrypted packet to
communicate various pieces of information including desired access through an
iptables or ipfw policy and/or specific commands to execute on the target system.
The main application of this program is to protect services such as SSH with
an additional layer of security in order to make the exploitation of
vulnerabilities (both 0-day and unpatched code) much more difficult.  The
authorization server passively monitors authorization packets via libpcap and
hence there is no "server" to which to connect in the traditional sense.  Any
service protected by fwknop is inaccessible (by using iptables or ipfw to
intercept packets within the kernel) before authenticating; anyone scanning for
the service will not be able to detect that it is even listening.  This
authorization scheme offers many advantages over port knocking, include being
non-replayable, much more data can be communicated, and the scheme cannot be
broken by simply connecting to extraneous ports on the server in an effort to
break knock sequences.  The authorization packets can easily be spoofed as
well, and this makes it possible to make it appear as though, say,
www.yahoo.com is trying to authenticate to a target system but in reality the
actual connection will come from a seemingly unrelated IP. Although the
default data collection method is to use libpcap to sniff packets off the
wire, fwknop can also read packets out of a file that is written by the
iptables ulogd pcap writer or by a separate sniffer process.

%prep
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%setup -q

%build
### build fwknop binaries (knopmd and knopwatchd)
make OPTS="$RPM_OPT_FLAGS"

%install
### log directory
mkdir -p $RPM_BUILD_ROOT%fwknoplogdir
### dir for fwknopfifo
### dir for pidfiles
mkdir -p $RPM_BUILD_ROOT%fwknoprundir

mkdir -p $RPM_BUILD_ROOT%_bindir
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man8
mkdir -p $RPM_BUILD_ROOT%_sbindir

### fwknop config
mkdir -p $RPM_BUILD_ROOT%_sysconfdir/%name
### fwknop init script
mkdir -p $RPM_BUILD_ROOT%_initrddir

install -m 755 fwknop $RPM_BUILD_ROOT%_bindir/
install -m 500 fwknopd $RPM_BUILD_ROOT%_sbindir/
install -m 500 knopmd $RPM_BUILD_ROOT%_sbindir/
install -m 500 fwknop_serv $RPM_BUILD_ROOT%_sbindir/
install -m 500 knopwatchd $RPM_BUILD_ROOT%_sbindir/
install -m 500 knoptm $RPM_BUILD_ROOT%_sbindir/
install -m 755 init-scripts/fwknop-init.redhat $RPM_BUILD_ROOT%_initrddir/fwknop
install -m 644 access.conf $RPM_BUILD_ROOT%_sysconfdir/%name/
install -m 644 fwknop.conf $RPM_BUILD_ROOT%_sysconfdir/%name/
install -m 644 pf.os $RPM_BUILD_ROOT%_sysconfdir/%name/
install -m 644 *.8 $RPM_BUILD_ROOT%{_mandir}/man8/

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%pre
#chmod 0600 /var/lib/fwknop/fwknopfifo

%post
### put the current hostname into various config files
perl -p -i -e 'use Sys::Hostname; my $hostname = hostname(); s/HOSTNAME(\s+)_?CHANGE.?ME_?/HOSTNAME${1}$hostname/' %_sysconfdir/%name/fwknop.conf

#/bin/touch %fwknoplogdir/fwdata
#chown root.root %fwknoplogdir/fwdata
### make fwknop start at boot
/sbin/chkconfig --add fwknop
if grep -q "EMAIL.*root.*localhost" /etc/fwknop/fwknop.conf;
then
echo "[+] You can edit the EMAIL_ADDRESSES variable in /etc/fwknop/fwknop.conf"
echo "    /etc/fwknop/fwknop.conf to have email alerts sent to an address"
echo "    other than root\@localhost"
fi

%preun
#%_preun_service fwknop

%files
%defattr(-,root,root)
%dir %fwknoplogdir
%dir %fwknoprundir
%_initrddir/*
%_sbindir/*
%_bindir/*
%{_mandir}/man8/*

%dir %_sysconfdir/%name
%config(noreplace) %_sysconfdir/%name/*.conf
%config(noreplace) %_sysconfdir/%name/pf.os

%changelog
* Mon Sep 07 2008 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.12

* Mon May 11 2008 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.11

* Mon Jan 12 2009 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.10

* Thu Nov 13 2008 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.9

* Tue Sep 30 2008 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.8

* Sun Aug 24 2008 Michael Rash <mbr@cipherdyne.org>
- This is the "nodeps" version of the fwknop.spec file - this version does
  not install any fwknop perl module dependencies.
- Release of fwknop-1.9.7

* Fri Jul 18 2008 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.6

* Sun Jun 08 2008 Michael Rash <mbr@cipherdyne.org>
- Removed List::MoreUtils since the updated Net::RawIP module no longer
  requires it as a dependency.
- Release of fwknop-1.9.5

* Sun Jun 01 2008 Michael Rash <mbr@cipherdyne.org>
- Added Digest::SHA
- Release of fwknop-1.9.4

* Sat Apr 05 2008 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.3

* Wed Mar 12 2008 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.2

* Sat Jan 26 2008 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.1

* Sat Dec 15 2007 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.0

* Sat Nov 17 2007 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.8.3

* Sat Sep 15 2007 Michael Rash <mbr@cipherdyne.org>
- Updated Crypt::Rjindael module to version 1.04 to solve the issue where
  encrypt/decrypt cycle would fail across 64 to 32-bit processors (or vice
  versa).
- Release of fwknop-1.8.2

* Wed Jun 06 2007 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.8.1

* Sun Jun 03 2007 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.8

* Tue Jan 09 2007 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.0.1

* Sun Nov 05 2006 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.0

* Sun Nov 05 2006 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.0

* Sun Oct 15 2006 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-0.9.9

* Sun Sep 17 2006 Michael Rash <mbr@cipherdyne.org>
- Adapted patch that Mate Wierdl contributed to the psad project to get the
  fwknop RPM building on x86_64 platforms.
- Removed iptables requirement since fwknop may be installed on a system just
  to run the fwknop client.
- Release of fwknop-0.9.8

* Fri Aug 04 2006 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-0.9.7
- Added fwknop_serv for TCP-based SPA connections.

* Fri Jan 13 2006 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-0.9.6
- Added the GnuPG-Interface and Class-MethodMaker perl modules for GPG
  encryption/decryption.

* Sun Oct 2 2005 Michael Rash <mbr@cipherydne.org>
- Release of fwknop-0.9.5

* Fri Sep 16 2005 Michael Rash <mbr@cipherydne.org>
- Initial RPM release.
