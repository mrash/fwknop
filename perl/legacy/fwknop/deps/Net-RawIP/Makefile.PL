use ExtUtils::MakeMaker;
use Config;
use strict;
use warnings;

my %config = (
    'linux' => [
        '-D_LINUX_ -D_ETH_ -D_IFLIST_ ' . (defined $ENV{CFLAGS} ? $ENV{'CFLAGS'} : ''),
        'RawIP.o util.o eth.o ifaddrlist.o',
        '',
        q{$def .= ' -D_GLIBC_' if -e "/usr/include/net/if_packet.h"}, 
    ],
              
    'solaris' => [ 
        '-D_SOLARIS_ -D_IFLIST_',
        'RawIP.o util.o ifaddrlist.o',
        "Sorry,ethernet related methods are not implemented on Solaris\n"
        . "Sorry, the rdev function is not imlemented on Solaris\n",
        '',         
    ],
            
    'freebsd' => [ 
        '-D_BSDRAW_ -D_ETH_ -D_BPF_ -D_IFLIST_ -DHAVE_SOCKADDR_SA_LEN',
        'RawIP.o util.o ifaddrlist.o eth.o rdev.o',
        '',
        '',
    ],
              
    'netbsd' => [
        '-D_BSDRAW_ -D_ETH_ -D_BPF_ -D_IFLIST_ -DHAVE_SOCKADDR_SA_LEN',
        'RawIP.o util.o ifaddrlist.o eth.o rdev.o',
        '',
        '',
    ],
                    
    'bsdos' => [
        '-D_BSDRAW_ -D_ETH_ -D_BPF_ -D_IFLIST_ -DHAVE_SOCKADDR_SA_LEN',
        'RawIP.o util.o ifaddrlist.o eth.o rdev.o',
        '',
        '',
    ],

    'openbsd' => [
        '-D_ETH_ -D_BPF_ -D_IFLIST_ -DHAVE_SOCKADDR_SA_LEN',
        'RawIP.o util.o ifaddrlist.o eth.o rdev.o',
        '',
        q{$def .= ' -D_BSDRAW_' if join('',(split /\./,$Config{osvers})[0,1]) < 21},
    ],
      
    'others'   => [
        '',
        'RawIP.o util.o',
        "Sorry,ethernet related methods are not implemented on this system\n"
        . "Sorry, the ifaddrlist function is not imlemented on this system\n"
        . "Sorry, the rdev function is not imlemented on this system\n",
        '',
    ]
);          

my $name = $Config{osname}; 
if (not exists $config{$name}) {
    $name = 'others';
}
my $def = $config{$name}->[0];
my $obj = $config{$name}->[1];
print $config{$name}->[2];
eval $config{$name}->[3];

print "Compiler: $Config{cc}\n";
system "$Config{cc} --version";

locate_pcap();


WriteMakefile(
    NAME           => 'Net::RawIP',
    VERSION_FROM   => 'lib/Net/RawIP.pm', 
    LIBS           => ['-lpcap'],   
    DEFINE         => $def,      
    INC            => '',      
    OBJECT         => $obj,
    PREREQ_PM      => {
    },
);


# on Ubuntu file locations:
# /usr/lib/libpcap.so.0.8
# /usr/lib/libpcap.so.0.9.4
# /usr/lib/libpcap.so.0.7.2
# /usr/lib/libpcap.so.0.7
# /usr/lib/libpcap.a
# /usr/lib/libpcap.so

# /usr/include/pcap.h
sub locate_pcap {
    my $header = '/usr/include/pcap.h';

    if (! -e $header) {
        print <<'END_REPORT';
Could not find libpcap, see the README file how to install it.

If you do have libpcap installed, please let me know the
locations of the pcap.h file and what operating system are you using
so I can include it in the next release

END_REPORT
        die "Could not find pcap.h. Makefile.PL was not created.\n";
    }

    open my $fh, '<', $header or die "Could not open $header for reading: $!";
    while (my $line = <$fh>) {
        if ($line =~ /PCAP_VERSION/) {
            print $line;
        }
    }


    print "The following libpcap.so files were found:\n\n";
    my @so_files = glob "/usr/lib/libpcap.so*";
    die "No libpcap.so file found. Makefile.PL was not created.\n"
        if not @so_files;
    print map {"$_\n"} @so_files;
}

