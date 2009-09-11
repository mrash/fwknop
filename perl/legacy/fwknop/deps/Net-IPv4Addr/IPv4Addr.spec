Summary: Perl modules to manipulates Ipv4 addresses.
Name: Net-IPv4Addr
Version: 0.10
Release: 1i
Source: http://iNDev.iNsu.COM/sources/%{name}-%{version}.tar.gz
Copyright: GPL or Artistic License
Group: Development/Libraries
Prefix: /usr
URL: http://iNDev.iNsu.COM/IPv4Addr/
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildArchitectures: noarch
Obsoletes: Network-IPv4Addr

%description
Net::IPv4Addr provides methods for parsing IPv4
addresses both in traditional address/netmask format and
in the new CIDR format.  There are also methods for
calculating the network and broadcast address and also to
see check if a given address is in a specific network.

%prep
%setup -q
%fix_perl_path

%build
perl Makefile.PL 
make OPTIMIZE="$RPM_OPT_FLAGS"
make test

%install
rm -fr $RPM_BUILD_ROOT
%perl_make_install

BuildDirList > %pkg_file_list
BuildFileList >> %pkg_file_list

%clean
rm -fr $RPM_BUILD_ROOT

%files -f %{name}-file-list
%defattr(-,root,root)
%doc README ChangeLog

%changelog
* Tue Aug 01 2000  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.10-1i]
- Updated to version 0.10.
- Updated spec file to use new macros.

* Wed May 03 2000  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.09-1i]
- Updated to version 0.09.
- Updated automatic file list generation.
- Changed group.

* Wed Dec 15 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.08-1i]
- Updated to version 0.08.
- Added perl(Net::IPv4Addr) to list of Provides.
- Fixed Source URL.

* Tue Oct 19 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.07-1i]
- Updated to version 0.07

* Tue Oct 19 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.06-1i]
- Updated to version 0.06.
- Renamed package to Net-IPv4Addr.

* Wed Sep 15 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.05-1i]
- Updated to version 0.05.

* Sun Aug 15 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.04-1i]
- Updated to version 0.04.

* Mon Jul 05 1999  Francis J. Lacoste <francis.lacoste@iNsu.COM> 
  [0.03-1i]
- Updated to version 0.03.

* Sat May 15 1999  Francis J. Lacoste <francis@iNsu.COM> 
  [0.02-2i]
- Updated to version 0.02.

* Sat May 15 1999  Francis J. Lacoste <francis@iNsu.COM> 
  [0.01-1i]
- First RPM release.

