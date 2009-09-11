%define name fwknop
%define version 1.9.12
%define release 1
%define fwknoplibdir %_libdir/%name
%define fwknoplogdir /var/log/fwknop
%define fwknoprundir /var/run/fwknop
#%define fwknopvarlibdir /var/lib/fwknop

### get the first @INC directory that includes the string "linux".
### This may be 'i386-linux', or 'i686-linux-thread-multi', etc.
%define fwknopmoddir `perl -e '$path='i386-linux'; for (@INC) { if($_ =~ m|.*/(.*linux.*)|) {$path = $1; last; }} print $path'`

Summary: Fwknop implements Single Packet Authorization (SPA) around iptables
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

cd deps
cd Unix-Syslog && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd IPTables-Parse && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd IPTables-ChainMgr && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd Crypt-CBC && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd Crypt-Rijndael && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd Digest-SHA && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd Class-MethodMaker && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd GnuPG-Interface && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd Net-Ping-External && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd Net-Pcap && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd Net-RawIP && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd Net-IPv4Addr && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ..
cd TermReadKey && perl Makefile.PL PREFIX=%fwknoplibdir LIB=%fwknoplibdir
cd ../..

%build
### build fwknop binaries (knopmd and knopwatchd)
make OPTS="$RPM_OPT_FLAGS"

### build perl modules used by fwknop
cd deps
make OPTS="$RPM_OPT_FLAGS" -C Unix-Syslog
make OPTS="$RPM_OPT_FLAGS" -C IPTables-Parse
make OPTS="$RPM_OPT_FLAGS" -C IPTables-ChainMgr
make OPTS="$RPM_OPT_FLAGS" -C Crypt-CBC
make OPTS="$RPM_OPT_FLAGS" -C Crypt-Rijndael
make OPTS="$RPM_OPT_FLAGS" -C Digest-SHA
make OPTS="$RPM_OPT_FLAGS" -C Class-MethodMaker
make OPTS="$RPM_OPT_FLAGS" -C GnuPG-Interface
make OPTS="$RPM_OPT_FLAGS" -C Net-Ping-External
make OPTS="$RPM_OPT_FLAGS" -C Net-Pcap
make OPTS="$RPM_OPT_FLAGS" -C Net-RawIP
make OPTS="$RPM_OPT_FLAGS" -C Net-IPv4Addr
make OPTS="$RPM_OPT_FLAGS" -C TermReadKey
cd ..

%install
### log directory
mkdir -p $RPM_BUILD_ROOT%fwknoplogdir
### dir for fwknopfifo
#mkdir -p $RPM_BUILD_ROOT%fwknopvarlibdir
### dir for pidfiles
mkdir -p $RPM_BUILD_ROOT%fwknoprundir

### fwknop module dirs
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Unix/Syslog
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Net/IPv4Addr
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Net/Pcap
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Net/Ping
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Net/RawIP
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Term/ReadKey
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/IPTables/Parse
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/IPTables/ChainMgr
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Crypt/Rijndael
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Digest/SHA
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Crypt/CBC
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Class/MethodMaker/array
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Class/MethodMaker/Engine
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Class/MethodMaker/hash
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Class/MethodMaker/scalar
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Unix
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Crypt
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Digest
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Class/MethodMaker
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Term
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/RawIP
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/auto/Net/IPv4Addr
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/auto/GnuPG/Interface
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/Crypt
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/GnuPG
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/Net
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/Net/Ping
mkdir -p $RPM_BUILD_ROOT%fwknoplibdir/IPTables
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

### install perl modules used by fwknop
cd deps
install -m 555 Unix-Syslog/blib/arch/auto/Unix/Syslog/Syslog.so $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Unix/Syslog/Syslog.so
install -m 444 Unix-Syslog/blib/arch/auto/Unix/Syslog/Syslog.bs $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Unix/Syslog/Syslog.bs
install -m 444 Unix-Syslog/blib/lib/auto/Unix/Syslog/autosplit.ix $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Unix/Syslog/autosplit.ix
install -m 444 Unix-Syslog/blib/lib/Unix/Syslog.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Unix/Syslog.pm
install -m 444 IPTables-Parse/blib/lib/IPTables/Parse.pm $RPM_BUILD_ROOT%fwknoplibdir/IPTables/Parse.pm
install -m 444 IPTables-ChainMgr/blib/lib/IPTables/ChainMgr.pm $RPM_BUILD_ROOT%fwknoplibdir/IPTables/ChainMgr.pm
install -m 444 Crypt-CBC/blib/lib/Crypt/CBC.pm $RPM_BUILD_ROOT%fwknoplibdir/Crypt/CBC.pm
install -m 444 Class-MethodMaker/blib/lib/auto/Class/MethodMaker/array/*.* $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Class/MethodMaker/array/
install -m 444 Class-MethodMaker/blib/lib/auto/Class/MethodMaker/scalar/*.* $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Class/MethodMaker/scalar/
install -m 444 Class-MethodMaker/blib/lib/auto/Class/MethodMaker/hash/*.* $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Class/MethodMaker/hash/
install -m 444 Class-MethodMaker/blib/lib/auto/Class/MethodMaker/Engine/*.* $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Class/MethodMaker/Engine/
install -m 444 Class-MethodMaker/blib/arch/auto/Class/MethodMaker/MethodMaker.bs $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Class/MethodMaker/MethodMaker.bs
install -m 444 Class-MethodMaker/blib/arch/auto/Class/MethodMaker/MethodMaker.so $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Class/MethodMaker/MethodMaker.so
install -m 444 Class-MethodMaker/blib/lib/Class/MethodMaker.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Class/MethodMaker.pm
install -m 444 Class-MethodMaker/blib/lib/Class/MethodMaker/*.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Class/MethodMaker
install -m 444 GnuPG-Interface/blib/lib/auto/GnuPG/Interface/*.* $RPM_BUILD_ROOT%fwknoplibdir/auto/GnuPG/Interface/
install -m 444 GnuPG-Interface/blib/lib/GnuPG/*.pm $RPM_BUILD_ROOT%fwknoplibdir/GnuPG/
install -m 444 Crypt-Rijndael/blib/lib/Crypt/Rijndael.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Crypt/Rijndael.pm
install -m 444 Crypt-Rijndael/blib/arch/auto/Crypt/Rijndael/Rijndael.bs $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Crypt/Rijndael/Rijndael.bs
install -m 444 Crypt-Rijndael/blib/arch/auto/Crypt/Rijndael/Rijndael.so $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Crypt/Rijndael/Rijndael.so
install -m 444 Digest-SHA/blib/lib/Digest/SHA.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Digest/SHA.pm
install -m 444 Digest-SHA/blib/arch/auto/Digest/SHA/SHA.bs $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Digest/SHA/SHA.bs
install -m 444 Digest-SHA/blib/arch/auto/Digest/SHA/SHA.so $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Digest/SHA/SHA.so
install -m 444 Net-Ping-External/blib/lib/Net/Ping/External.pm $RPM_BUILD_ROOT%fwknoplibdir/Net/Ping/External.pm
install -m 444 Net-Pcap/blib/lib/Net/Pcap.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/Pcap.pm
install -m 444 Net-Pcap/blib/arch/auto/Net/Pcap/Pcap.bs $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Net/Pcap/Pcap.bs
install -m 444 Net-Pcap/blib/arch/auto/Net/Pcap/Pcap.so $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Net/Pcap/Pcap.so
install -m 444 Net-RawIP/blib/lib/Net/RawIP.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/RawIP.pm
install -m 444 Net-RawIP/blib/lib/Net/RawIP/ethhdr.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/RawIP/ethhdr.pm
install -m 444 Net-RawIP/blib/lib/Net/RawIP/generichdr.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/RawIP/generichdr.pm
install -m 444 Net-RawIP/blib/lib/Net/RawIP/icmphdr.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/RawIP/icmphdr.pm
install -m 444 Net-RawIP/blib/lib/Net/RawIP/iphdr.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/RawIP/iphdr.pm
install -m 444 Net-RawIP/blib/lib/Net/RawIP/opt.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/RawIP/opt.pm
install -m 444 Net-RawIP/blib/lib/Net/RawIP/tcphdr.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/RawIP/tcphdr.pm
install -m 444 Net-RawIP/blib/lib/Net/RawIP/udphdr.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/RawIP/udphdr.pm
install -m 444 Net-RawIP/blib/lib/Net/RawIP/libpcap.pod $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Net/RawIP/libpcap.pod
install -m 444 Net-RawIP/blib/arch/auto/Net/RawIP/RawIP.bs $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Net/RawIP/RawIP.bs
install -m 444 Net-RawIP/blib/arch/auto/Net/RawIP/RawIP.so $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Net/RawIP/RawIP.so
install -m 444 Net-RawIP/blib/lib/auto/Net/RawIP/autosplit.ix $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Net/RawIP/autosplit.ix
install -m 444 Net-IPv4Addr/blib/lib/auto/Net/IPv4Addr/autosplit.ix $RPM_BUILD_ROOT%fwknoplibdir/auto/Net/IPv4Addr/autosplit.ix
install -m 444 Net-IPv4Addr/blib/lib/Net/IPv4Addr.pm $RPM_BUILD_ROOT%fwknoplibdir/Net/IPv4Addr.pm
install -m 444 TermReadKey/blib/lib/Term/ReadKey.pm $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/Term/ReadKey.pm
install -m 444 TermReadKey/blib/lib/auto/Term/ReadKey/autosplit.ix $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Term/ReadKey/autosplit.ix
install -m 444 TermReadKey/blib/arch/auto/Term/ReadKey/ReadKey.bs $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Term/ReadKey/ReadKey.bs
install -m 444 TermReadKey/blib/arch/auto/Term/ReadKey/ReadKey.so $RPM_BUILD_ROOT%fwknoplibdir/%fwknopmoddir/auto/Term/ReadKey/ReadKey.so
cd ..

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
#%dir %fwknopvarlibdir
%dir %fwknoprundir
%_initrddir/*
%_sbindir/*
%_bindir/*
%{_mandir}/man8/*

%dir %_sysconfdir/%name
%config(noreplace) %_sysconfdir/%name/*.conf
%config(noreplace) %_sysconfdir/%name/pf.os

%_libdir/%name

%changelog
* Mon Sep 07 2009 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.12

* Mon May 11 2009 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.11

* Mon Jan 12 2009 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.10

* Thu Nov 13 2008 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.9

* Tue Sep 30 2008 Michael Rash <mbr@cipherdyne.org>
- Release of fwknop-1.9.8

* Sun Aug 24 2008 Michael Rash <mbr@cipherdyne.org>
- Removed 'use lib' editing code
- Updated to use the deps/ directory for all perl module sources.
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
