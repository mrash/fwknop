# Main package 
package Net::RawIP;
use strict;
use warnings;

use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $AUTOLOAD);
use subs qw(timem ifaddrlist);

use English qw( -no_match_vars );
use Net::RawIP::iphdr;
use Net::RawIP::tcphdr;
use Net::RawIP::udphdr;
use Net::RawIP::icmphdr;
use Net::RawIP::generichdr;
use Net::RawIP::opt;
use Net::RawIP::ethhdr;

require Exporter;
require DynaLoader;
require AutoLoader;
@ISA = qw(Exporter DynaLoader);

@EXPORT = qw(timem open_live dump_open dispatch dump loop linkoffset ifaddrlist rdev);
@EXPORT_OK = qw(
PCAP_ERRBUF_SIZE PCAP_VERSION_MAJOR PCAP_VERSION_MINOR lib_pcap_h
open_live open_offline dump_open lookupdev lookupnet dispatch
loop dump compile setfilter next datalink snapshot is_swapped major_version
minor_version stats file fileno perror geterr strerror close dump_close);  

%EXPORT_TAGS = ( 'pcap' => [
qw(
PCAP_ERRBUF_SIZE PCAP_VERSION_MAJOR PCAP_VERSION_MINOR lib_pcap_h
open_live open_offline dump_open lookupdev lookupnet dispatch
loop dump compile setfilter next datalink snapshot is_swapped major_version
minor_version stats file fileno perror geterr strerror close dump_close
timem linkoffset ifaddrlist rdev)  
                            ]
);

$VERSION = '0.23';

# The number of members in the sub modules
my %n = (
    tcp     => 17,
    udp     => 5,
    icmp    => 9,
    generic => 1,
); 
my @valid_protocols = qw(tcp udp icmp generic);

sub AUTOLOAD {
    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "& not defined" if $constname eq 'constant';
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
        if ($! =~ /Invalid/) {
            $AutoLoader::AUTOLOAD = $AUTOLOAD;
            goto &AutoLoader::AUTOLOAD;
        }
        else {
            croak "Your vendor has not defined Net::RawIP macro $constname";
        }
    }
    *$AUTOLOAD = sub () { $val };
    goto &$AUTOLOAD;
}
bootstrap Net::RawIP $VERSION;

# Warn if called from non-root accounts
# TODO: move this warning only when calling functions that really need root
# priviliges
carp "Must have EUID == 0 to use Net::RawIP, currently you are seen with EUID=$EUID" if $EUID;


# The constructor
sub new {
    my ($proto, $ref) = @_;
    my $class = ref($proto) || $proto;
    my $self = {};
    bless $self, $class;

    # Determine which protocol (tcp by default) 
    $ref ||= {};
    foreach my $k (keys %$ref) {
        croak "'$k' is not a valid key\n" 
            if not grep {$_ eq $k} (@valid_protocols, 'ip');
    }
    $self->proto($ref);

    $self->_unpack($ref);;
    return $self
}

sub proto {
    my ($class, $args) = @_;
    if (not $class->{proto}) {
        my $proto;
        foreach my $p (@valid_protocols) {
            if (exists $args->{$p}) {
                croak "Duplicate protocols defined: '$proto' and '$p'\n"
                    if $proto;
                $proto = $p;
            }
        }
        $proto ||= 'tcp';
        $class->{proto} = $proto;
    }
    return $class->{proto}
}

# IP and TCP options 
sub optset {
    my ($class, %arg) = @_;


    # Initialize Net::RawIP::opt objects from argument
    foreach my $optproto (sort keys %arg) {
        my $option = "opts$optproto";
        if (not $class->{$option}) {
            $class->{$option} = Net::RawIP::opt->new;
        }
        @{$class->{$option}->type} = ();
        @{$class->{$option}->len}  = ();
        @{$class->{$option}->data} = ();
        foreach my $k (keys %{ $arg{$optproto} }) {
            @{ $class->{$option}->$k() } = @{ $arg{$optproto}->{$k} };
        }

        # Compute lengths of options 
        foreach my $i (0..@{ $arg{$optproto}->{data} }-1) {
            my $len = length($class->{$option}->data($i));
            $len = 38 if $len > 38;
            $class->{$option}->len($i, 2+$len);
        }

        # Fill an array with types,lengths,datas and put the reference of this array  
        # to the sub module as last member   
        my @array;
        foreach my $i (0 .. @{ $class->{$option}->type }-1 ) {
            push @array, (
                    $class->{$option}->type($i), 
                    $class->{$option}->len($i), 
                    $class->{$option}->data($i)
                );
        }

        my $i = 0;
        if ($optproto eq 'tcp') {
            $i = 1;
            $class->{tcphdr}->[17] = 0 unless defined $class->{tcphdr}->[17];
        }
        ${ $class->{"$class->{proto}hdr"} }[ $i + $n{$class->{proto}} ] = [(@array)]
    }

    # Repacking current packet
    return $class->_pack(1);
}

sub optget {
    my ($class, %arg) = @_;
    my @array;
    foreach my $optproto (sort keys %arg) {
        # Get whole array if not specified type of option
        if (!exists $arg{$optproto}->{type}) {
            my $i = 0;
            if ($optproto eq 'tcp'){
                $i = 1;
            }
            push @array,
                (@{${$class->{"$class->{proto}hdr"}}[$i+$n{$class->{proto}}]});
        }
        else {
            # Get array filled with specified options 
            foreach my $type (@{ $arg{$optproto}->{type} }) {
                my $option = "opts$optproto";
                foreach my $i (0 .. @{ $class->{$option}->type() }-1 ) {
                    if ($type == $_) {
                        push @array,($class->{$option}->type($i));       
                        push @array,($class->{$option}->len($i));       
                        push @array,($class->{$option}->data($i));       
                    }
                }
            }
        } 
    }

    return (@array)
}

sub optunset {
    my($class, @arg) = @_;

    my $i = 0;
    foreach my $optproto (sort @arg) {
        if ($optproto eq 'tcp') {
            $i = 1;
            # Look at RFC
            $class->{tcphdr}->doff(5);
        }
        else {
            # Look at RFC
            $class->{iphdr}->ihl(5);
        }
        $class->{"opts$optproto"} = 0;
        ${$class->{"$class->{proto}hdr"}}[$i+$n{$class->{proto}}] = 0;
    }
    return $class->_pack(1);
}

# An ethernet related initialization
# We open descriptor and get hardware and IP addresses of device by tap()   
sub ethnew {
    my ($class, $dev, @arg) = @_;

    my ($ip, $mac);
    $class->{ethhdr}  = Net::RawIP::ethhdr->new; 
    $class->{tap}     = tap($dev, $ip, $mac);
    $class->{ethdev}  = $dev;
    $class->{ethmac}  = $mac;
    $class->{ethip}   = $ip; 
    $class->{ethhdr}->dest($mac);
    $class->{ethhdr}->source($mac); 
    my $ipproto       = pack ("n1",0x0800);
    $class->{ethpack} =
        $class->{ethhdr}->dest . $class->{ethhdr}->source . $ipproto;
    $class->ethset(@arg) if @arg;
}


sub ethset {
    my ($self, %hash) = @_;
    map { $self->{ethhdr}->$_($hash{$_}) } keys %hash;
    my $source = $self->{ethhdr}->source;
    my $dest   = $self->{ethhdr}->dest;
 
    if ($source =~ /^(\w\w):(\w\w):(\w\w):(\w\w):(\w\w):(\w\w)$/) {
        $self->{ethhdr}->source(
            pack("C6",hex($1),hex($2),hex($3),hex($4),hex($5),hex($6))
        );
        $source = $self->{ethhdr}->source;
    }

    if ($dest =~ /^(\w\w):(\w\w):(\w\w):(\w\w):(\w\w):(\w\w)$/) {
        $self->{ethhdr}->dest(
            pack("C6", hex($1),hex($2),hex($3),hex($4),hex($5),hex($6))
        );
        $dest = $self->{ethhdr}->dest;
    }

    # host_to_ip returns IP address of target in host byteorder format
    $self->{ethhdr}->source(mac(host_to_ip($source)))
    unless($source =~ /[^A-Za-z0-9\-.]/ && length($source) == 6);
    $self->{ethhdr}->dest(mac(host_to_ip($dest)))
    unless($dest =~ /[^A-Za-z0-9\-.]/ && length($dest) == 6);
    my $ipproto = pack ("n1",0x0800);
    $self->{ethpack}=$self->{ethhdr}->dest.$self->{ethhdr}->source.$ipproto;
}

# Lookup for mac address in the ARP cache table 
# If not successul then send ICMP packet to target and retry lookup
sub mac {
    my ($ip) = @_;
    my $mac;

    return $mac if mac_disc($ip, $mac);

    my $obj = Net::RawIP->new({
                        ip => {
                            saddr => 0,
                            daddr => $ip,
                        },
                        icmp => {},
                    });
    $obj->send(1,1);
    return $mac if mac_disc($ip,$mac);

    my $ipn = sprintf("%u.%u.%u.%u", unpack("C4", pack("N1",$ip)));
    croak "Can't discover MAC address for $ipn";
}

sub ethsend {
    my ($self, $delay, $times) = @_;
    $times ||= 1;

    for (1..$times) {
        # The send_eth_packet takes the descriptor,the name of device,the scalar
        # with packed ethernet packet and the flag (0 - non-ip contents,1 - otherwise)  
        send_eth_packet(
            $self->{tap},
            $self->{ethdev},
            $self->{ethpack} . $self->{pack},
            1);
        sleep $delay if $delay;
    }
}

# Allow to send any frames
sub send_eth_frame {
    my ($self, $frame, $delay, $times) = @_;
    $times ||= 1;

    for (1..$times) {
        send_eth_packet(
            $self->{tap},
            $self->{ethdev},
            substr($self->{ethpack}, 0, 12) . $frame,
            0);
        sleep $delay if $delay;
    }
} 

# The initialization with default values
sub _unpack {
    my ($self, $ref) = @_;

    $self->{iphdr} = Net::RawIP::iphdr->new;

    my $class = 'Net::RawIP::' . $self->{proto} . 'hdr';
    $self->{"$self->{proto}hdr"} = $class->new;

    my $default_method = $self->{proto} . '_default';
    $self->$default_method;

    $self->set($ref);
}

sub tcp_default {
    my ($class) = @_;
    @{$class->{iphdr}} = (4,5,16,0,0,0x4000,64,6,0,0,0);
    @{$class->{tcphdr}} = (0,0,0,0,5,0,0,0,0,0,0,0,0,0xffff,0,0,'');
}

sub udp_default {
    my ($class) = @_;
    @{$class->{iphdr}} = (4,5,16,0,0,0x4000,64,17,0,0,0);
    @{$class->{udphdr}} = (0,0,0,0,'');
}

sub icmp_default {
    my ($class) = @_;
    @{$class->{iphdr}} = (4,5,16,0,0,0x4000,64,1,0,0,0);
    @{$class->{icmphdr}} = (0,0,0,0,0,0,0,0,'');
}

sub generic_default {
    my ($class) = @_;
    @{$class->{iphdr}} = (4,5,16,0,0,0x4000,64,0,0,0,0);
    @{$class->{generichdr}} = ('');
}

# 2xS = 16bits
# 1xI = 32bits or more
# Byte ordering is unspecified, so it's probably native ordering.
# To me using I seems like a bad idea since in some cases this might
# be more than 32 bits yet the network structures require exactly
# 32 bits, plus they must always be in network byte order (big-endian)
# Steve Bonds
sub s2i {
    return unpack("I1", pack("S2", @_))
}

# This lies a bit-- the original values passed in may not be in
# network byte order but this will reverse them on little-endian hosts
# while (hopefully) leaving them alone on big-endian hosts, resulting
# in the correct on-the-wire byte ordering.  Steve Bonds
sub n2L {
    return unpack("L1", pack("n2", @_));
}

# This does the same thing, but for the whole 32 bits at once, suitable
# for ICMP packets with the gateway hash key set.
sub N2L {
    return unpack("L1", pack("N1", @_));
}

sub _pack {
    my $self = shift;
    if (@_) {
        # A low level *_pkt_creat() functions take reference of array 
        # with all of fields of the packet and return properly packed scalar  
        # These are defined in the Raw.xs file.
        my $function = $self->{proto} . '_pkt_creat';
        ## no critic (ProhibitNoStrict)
        no strict 'refs';
        # not clear to me what is undef here but it trips one of the tests
        no warnings; 
        my @array = (@{$self->{iphdr}}, @{$self->{"$self->{proto}hdr"}});
        $self->{pack} = $function->(\@array);
    }

    return $self->{pack};
}

sub packet {
    my $class = shift;
    return $class->_pack
}

sub set {
    my ($self, $hash) = @_;
    # To handle C union in the ICMP header.  That C union is either:
    # struct
    # {
    #   u_int16_t id;
    #   u_int16_t sequence;
    # } echo;         /* echo datagram */
    # u_int32_t   gateway;    /* gateway address */
    # struct
    # {
    #   u_int16_t unused;
    #   u_int16_t mtu;
    # } frag;         /* path mtu discovery */
    # So we can either set:
    #  + id and sequence, or
    #  + a single gateway address, or
    #  + unused and MTU

    # My guess is that this exists simply to make it easier to call
    # things in Perl by the same name as the C union.  Steve Bonds
    my %un = (
            id     => 'sequence',
            unused => 'mtu',
    );
    my %revun = reverse %un;

    # See Class::Struct
    if (exists $hash->{ip}) {
        foreach my $k (keys %{ $hash->{ip} }) {
            $self->{iphdr}->$k( $hash->{ip}->{$k});
        } 
    }

    my $proto = $self->{proto};
    if (exists $hash->{$proto}) {
        foreach my $k (keys %{ $hash->{$proto} }) {
            $self->{"${proto}hdr"}->$k( $hash->{$proto}->{$k} )
        }
    }

    # This looks like a good spot to apply the endianness fixes for
    # id/sequence and/or mtu/unused.  Steve Bonds
    if (exists $hash->{icmp}) {
        foreach my $k (keys %{ $hash->{icmp} }) {
            $self->{icmphdr}->$k( $hash->{icmp}->{$k} );
            if ($k !~ /gateway/) {
                if ($un{$k}) { 
                    # if $k is "id" or "unused"
                    my $meth = $un{$k};
                    $self->{icmphdr}->gateway(n2L(
                       $self->{icmphdr}->$k(),
                       $self->{icmphdr}->$meth()
                    ));
                }       
                elsif ($revun{$k}) {
                    # if $k is "sequence" or "mtu"
                    my $meth = $revun{$k};
                    $self->{icmphdr}->gateway(n2L(
                       $self->{icmphdr}->$meth(),
                       $self->{icmphdr}->$k()
                    ));
                }
            } else {
              # $k =~ /gateway/
              # Not setting icmp => gateway since it's set by the user
              # However, it may still be in the wrong byte order so
              # reverse it if needed.  Steve Bonds
              $self->{icmphdr}->gateway(N2L( $hash->{icmp}->{gateway} ));
            }
        }
      }

    my $saddr = $self->{iphdr}->saddr;
    my $daddr = $self->{iphdr}->daddr;
    $self->{iphdr}->saddr(host_to_ip($saddr)) if ($saddr !~ /^-?\d*$/);
    $self->{iphdr}->daddr(host_to_ip($daddr)) if ($daddr !~ /^-?\d*$/);
    return $self->_pack(1);
}

sub bset {
    my ($self, $hash, $eth) = @_;

    if ($eth) {
        $self->{ethpack}   = substr($hash,0,14);
        $hash              = substr($hash,14);
        @{$self->{ethhdr}} = @{eth_parse($self->{ethpack})}
    }
    $self->{pack} = $hash;

    # The low level *_pkt_parse() functions take packet and return reference of
    # of the array with fields from this packet
    my $function = $self->{proto} . '_pkt_parse';
    ## no critic (ProhibitNoStrict)
    no strict 'refs';
    my $array = $function->($hash);
    use strict;

    my $proto_hdr = "$self->{proto}hdr";

    # Initialization of IP header object
    @{$self->{iphdr}} = @$array[0..10];
    # Initialization of sub IP object
    @{$self->{$proto_hdr}}= @$array[11..(@$array-1)];
    # If last member in the sub object is a reference of 
    # array with options then we have to initialize Net::RawIP::opt 
    if (ref(${$self->{$proto_hdr}}[$n{$self->{proto}}]) eq 'ARRAY') {
        my $j = 0;
        $self->{optsip} = Net::RawIP::opt->new  unless $self->{optsip};
        @{$self->{optsip}->type} = ();
        @{$self->{optsip}->len}  = ();
        @{$self->{optsip}->data} = ();
        for(my $i=0; $i<=(@{${$self->{$proto_hdr}}[$n{$self->{proto}}]} - 2); $i = $i + 3) {
            $self->{optsip}->type($j,
                ${${$self->{$proto_hdr}}[$n{$self->{proto}}]}[$i]);
            $self->{optsip}->len($j,
                ${${$self->{$proto_hdr}}[$n{$self->{proto}}]}[$i+1]);
            $self->{optsip}->data($j,
                ${${$self->{$proto_hdr}}[$n{$self->{proto}}]}[$i+2]);
            $j++;
        }
    }

    # For handle TCP options
    if($self->{proto} eq 'tcp') {
        if (ref(${$self->{tcphdr}}[18]) eq 'ARRAY') {
            my $j = 0;
            $self->{optstcp} = Net::RawIP::opt->new  unless $self->{optstcp};
            @{$self->{optstcp}->type} = ();
            @{$self->{optstcp}->len}  = ();
            @{$self->{optstcp}->data} = ();
            for (my $i=0; $i<=(@{${$self->{tcphdr}}[18]} - 2); $i = $i + 3) {
                $self->{optstcp}->type($j,
                    ${${$self->{tcphdr}}[18]}[$i]);
                $self->{optstcp}->len($j,
                    ${${$self->{tcphdr}}[18]}[$i+1]);
                $self->{optstcp}->data($j,
                    ${${$self->{tcphdr}}[18]}[$i+2]);
                $j++;
            }
        }
    }
}

sub get {
    my ($self, $hash) = @_;

    my $wantarray = wantarray;
    my %ref = (
        tcp     => \@Net::RawIP::tcphdr::tcphdr,
        udp     => \@Net::RawIP::udphdr::udphdr,
        icmp    => \@Net::RawIP::icmphdr::icmphdr,
        generic => \@Net::RawIP::generichdr::generichdr,
    );
    my @array;
    my %h;

    map { ${$$hash{ethh}}{$_} = '$' } @{$hash->{eth}};
    map { ${$$hash{iph}}{$_} = '$' } @{$hash->{ip}};
    map { ${$$hash{"$self->{proto}h"}}{$_} = '$' } @{$hash->{$self->{proto}}}; 

    if (exists $hash->{eth}) {
        foreach (@Net::RawIP::ethhdr::ethhdr) {
            if (defined $hash->{ethh}->{$_} and $hash->{ethh}->{$_} eq '$') {
                if ($wantarray) {    
                    push @array, $self->{ethhdr}->$_()
                }
                else {
                    $h{$_} = $self->{ethhdr}->$_()
                }  
            }
        }
    }

    if (exists $hash->{ip}) {
        foreach (@Net::RawIP::iphdr::iphdr) {
            if (defined $hash->{iph}->{$_} and $hash->{iph}->{$_} eq '$') {
                if ($wantarray) {    
                    push @array, $self->{iphdr}->$_()
                }
                else {
                    $h{$_} = $self->{iphdr}->$_()
                }
            }  
        }
    }

    if (exists $hash->{ $self->{proto} }) {
        my $proto_h   = "$self->{proto}h";
        my $proto_hdr = "$self->{proto}hdr";
        foreach (@{ $ref{$self->{proto}} }) {
            if (defined $hash->{$proto_h}->{$_} and $hash->{$proto_h}->{$_} eq '$') {
                if ($wantarray) {    
                    push @array,$self->{$proto_hdr}->$_()
                }
                else {
                    $h{$_} = $self->{$proto_hdr}->$_()
                }
            }  
        }
    }

    if ($wantarray) {
        return (@array);
    }
    else {
        return {%h}
    }
}

sub send {
    my ($self, $delay, $times) = @_;
    $times ||= 1;

    if (! $self->{raw}) {
        $self->{raw} = rawsock();
    }
    if ($self->{proto} eq 'icmp' || $self->{proto} eq 'generic') {
        $self->{sock} = set_sockaddr($self->{iphdr}->daddr,0);
    }
    else {
        $self->{sock} = set_sockaddr($self->{iphdr}->daddr,
                               $self->{"$self->{proto}hdr"}->dest);
    }
    for (1..$times) {
        pkt_send ($self->{raw}, $self->{sock}, $self->{pack});
        sleep $delay if $delay;
    }
} 

sub pcapinit {
    my ($self, $device, $filter, $size, $tout) = @_;
    my $promisc = 0x100;
    my ($erbuf, $program) = ('', 0);

    my $pcap = open_live($device,$size,$promisc,$tout,$erbuf);
    croak "Could not open_libe: '$erbuf'" if (! $pcap);
    croak "compile(): check string with filter" if (compile($pcap,$program,$filter,0,0) < 0);
    setfilter($pcap, $program);

    return $pcap
}

sub pcapinit_offline {
    my($self,$fname) = @_;
    my ($erbuf,$pcap);
    $pcap = open_offline($fname, $erbuf);
    croak $erbuf if (! $pcap);

    return $pcap;
}

sub rdev {
    my $rdev;
    my $ip = ($_[0] =~ /^-?\d+$/) ? $_[0] : host_to_ip($_[0]);
    my $ipn = unpack("I",pack("N",$ip));
    if (($rdev = ip_rt_dev($ipn)) eq 'proc'){
        my($dest,$mask);
        open (my $route, '<', '/proc/net/route') || croak "Can't open /proc/net/route: $!";
        while (<$route>) {
            next if /Destination/;
            ($rdev,$dest,$mask) = (split(/\s+/))[0,1,7];
            last unless ($ipn & hex($mask)) ^ hex($dest);
        }
        CORE::close($route);
        $rdev = 'lo' unless ($ip & 0xFF000000) ^ 0x7f000000; # For Linux 2.2.x 
    }
    croak "rdev(): Destination unreachable" unless $rdev;
    # The aliasing support
    $rdev =~ s/([^:]+)(:.+)?/$1/;
    return $rdev;    
}

sub DESTROY {
    my $self = shift;
    closefd($self->{raw}) if exists $self->{raw};
    closefd($self->{tap}) if exists $self->{tap};
}

1;
__END__

=head1 NAME

Net::RawIP - Perl extension for manipulate raw ip packets with interface to B<libpcap>

=head1 SYNOPSIS

  use Net::RawIP;
  $n = Net::RawIP->new({
                        ip  => {
                                saddr => 'my.target.lan',
                                daddr => 'my.target.lan',
                               },
                       });
                        tcp => {
                                source => 139,
                                dest   => 139,
                                psh    => 1,
                                syn    => 1,
                               },
                       });
  $n->send;
  $n->ethnew("eth0");
  $n->ethset(source => 'my.target.lan', dest =>'my.target.lan');    
  $n->ethsend;
  $p = $n->pcapinit("eth0", "dst port 21", 1500, 30);
  $f = dump_open($p, "/my/home/log");
  loop($p, 10, \&dump, $f);

=head1 DESCRIPTION

This package provides a class object which can be used for
creating, manipulating and sending raw ip packets with
optional features for manipulating ethernet headers.

B<NOTE:> Ethernet related methods are implemented on Linux and *BSD only

=head1 Exported constants

  PCAP_ERRBUF_SIZE
  PCAP_VERSION_MAJOR
  PCAP_VERSION_MINOR
  lib_pcap_h

=head1 Exported functions

open_live
open_offline
dump_open
lookupdev
lookupnet
dispatch
loop
dump
compile
setfilter
next
datalink
snapshot
is_swapped
major_version
minor_version
stats
file
fileno
perror
geterr
strerror
close
dump_close
timem
linkoffset
ifaddrlist
rdev

By default exported functions are the B<loop>, B<dispatch>, B<dump_open>, B<dump>,
B<open_live>, B<timem>, B<linkoffset>, B<ifaddrlist>, B<rdev>. 
You have to use the export tag B<pcap> for export all of the pcap functions.
Please read the docs for the libpcap and look at L<Net::RawIP::libpcap(3pm)>.

Please look at the examples in the examples/ folder of the distribution.

=head1 METHODS

=over 3

=item new

    Net::RawIP->new({
              ARGPROTO => {PROTOKEY => PROTOVALUE,...} 
              ip       => {IPKEY => IPVALUE,...},
      })          

B<ARGPROTO> is one of (B<tcp>, B<udp>, B<icmp>, B<generic>) defining the
protcol of the current packet. Defaults to B<tcp>.

You can B<NOT> change protocol in the object after its creation.  Unless you
want your packet to be TCP, you must set the protocol type in the new() call.

The possible values of B<PROTOKEY> depend on the value of ARGPROTO

If ARGPROTO is <tcp> PROTOKEY can be one of 
(B<source>, B<dest>, B<seq>, B<ack_seq>, B<doff>, B<res1>, B<res2>, 
B<urg>, B<ack>, B<psh>, B<rst>, B<syn>, B<fin>, B<window>, B<check>,
B<urg_ptr>, B<data>).

If ARGPROTO is B<icmp> PROTOKEY can be one of
(B<type>, B<code>, B<check>, B<gateway>, B<id>, B<sequence>, B<unused>, 
B<mtu>, B<data>).

If ARGPROTO is B<udp> PROTOKEY can be one of 
(B<source>, B<dest>, B<len>, B<check>, B<data>)

If ARGPROTO is B<generic> PROTOKEY can be B<data> only.

The B<data> entries are scalars containing packed network byte order
data.

As the real icmp packet is a C union one can specify specify only one 
of the following set of values.

=over 4

=item B<gateway> - (int)

=item (B<id> and B<sequence>) - (short and short)

=item (B<mtu> and B<unused>) - (short and short)

=back


The default values are 

(0,0,0,0,5,0,0,0,0,0,0,0,0,0xffff,0,0,'') for tcp

(0,0,0,0,0,0,0,0,'') for icmp

(0,0,0,0,'') for udp

('') for generic

The valid values for B<urg> B<ack> B<psh> B<rst> B<syn> B<fin> are 0 or 1.
The value of B<data> is a string. Length of the result packet will be calculated
if you do not specify non-zero value for B<tot_len>. 


The value of B<ip> is a hash defining the parameters of the IP header
(B<iphdr>) in the current IP packet.

B<IPKEY> is one of (B<version>, B<ihl>, B<tos>, B<tot_len>, B<id>,
B<frag_off>, B<ttl>, B<protocol>, B<check>, B<saddr>, B<daddr>).
You can to specify any and all of the above parameters.
If B<check> is not given checksum will be calculated automatically.

The values of the B<saddr> and the B<daddr> can be hostname
(e.g. www.oracle.com ) or IP address (205.227.44.16),
and even the integer value if you happen to know what is 205.227.44.16 
as an unsigned int in the host format ;). 

Examples:

    my $rawip = Net::RawIP->new({udp =>{}});

or

    my $rawip = Net::RawIP->new({ip => { tos => 22 }, udp => { source => 22,dest =>23 } });


The default values of the B<ip> hash are 

(4,5,16,0,0,0x4000,64,6,0,0,0) for B<tcp>

(4,5,16,0,0,0x4000,64,17,0,0,0) for B<udp>

(4,5,16,0,0,0x4000,64,1,0,0,0) for B<icmp>

(4,5,16,0,0,0x4000,64,0,0,0,0) for B<generic>


=item dump_open

If B<dump_open> opens and returns a valid file descriptor, this descriptor 
can be used in the perl callback as a perl filehandle. 

=item loop

=item dispatch

B<loop> and B<dispatch> can run a perl code refs as a callbacks for packet 
analyzing and printing.
the fourth parameter for B<loop> and B<dispatch> can be an array or a hash 
reference and it can be dereferenced in a perl callback. 

=item next

B<next> returns a string (next packet).

=item timem

B<timem()> returns a string that looks like B<sec>.B<microsec>, 
where the B<sec> and the B<microsec> are the values returned by
gettimeofday(3).
If B<microsec> is less than 100000 then zeros will be added to the 
left side of B<microsec> for adjusting to six digits.

Similar to sprintf("%.6f", Time::HiRes::time());

TODO: replace this function with use of Time::HiRes ?

=item linkoffset

The function which called B<linkoffset> returns a number of the bytes
in the link protocol header e.g. 14 for a Ethernet or 4 for a Point-to-Point
protocol. This function has one input parameter (pcap_t*) that is returned
by open_live.

=item ifaddrlist

B<ifaddrlist> returns a hash reference. In this hash keys are 
the running network devices, values are ip addresses of those devices 
in an internet address format.

=item rdev

B<rdev> returns a name of the outgoing device for given destination address.
It has one input parameter (destination address in an internet address
or a domain name or a host byteorder int formats).

=item proto

Returns the name of the subclass current object e.g. B<tcp>.
No input parameters.

=item packet

returns a scalar which contain the packed ip packet of the current object.
No input parameters.

=item set

is a method for set the parameters to the current object. The given parameters
must look like the parameters for the constructor.

=item bset($packet,$eth)

is a method for set the parameters for the current object.
B<$packet> is a scalar which contain binary structure (an ip or an eth packet).
This scalar must match with the subclass of the current object.
If B<$eth> is given and it have a non-zero value then assumed that packet is a
ethernet packet,otherwise it is a ip packet. 

=item get

is a method for get the parameters from the current object. This method returns
the array which will be filled with an asked parameters in order as they have ordered in
packet if you'd call it with an array context.
If this method is called with a scalar context then it returns a hash reference.
In that hash will stored an asked parameters as values,the keys are their names.
 
The input parameter is a hash reference. In this hash can be three keys.
They are a B<ip> and an one of the B<ARGPROTO>s. The value must be an array reference. This
array contain asked parameters.
E.g. you want to know current value of the tos from the iphdr and
the flags of the tcphdr.
Here is a code :

  ($tos,$urg,$ack,$psh,$rst,$syn,$fin) = $packet->get({
            ip => [qw(tos)],
        tcp => [qw(psh syn urg ack rst fin)]
        });

The members in the array can be given in any order.

For get the ethernet parameters you have to use the key B<eth> and the 
values of the array (B<dest>,B<source>,B<proto>). The values of the B<dest> and 
the B<source> will look like the output of the ifconfig(8) e.g. 00:00:E8:43:0B:2A. 

=item open_live



=item send($delay,$times)

is a method which has used for send raw ip packet.
The input parameters are the delay seconds and the times for repeating send.
If you do not specify parameters for the B<send>,then packet will be sent once
without delay. 
If you do specify for the times a negative value then packet will be sent forever.
E.g. you want to send the packet for ten times with delay equal to one second.
Here is a code :

$packet->send(1,10);
The delay could be specified not only as integer but 
and as 0.25 for sleep to 250 ms or 3.5 to sleep for 3 seconds and 500 ms.

=item pcapinit($device,$filter,$psize,$timeout)

is a method for some a pcap init. The input parameters are a device,a string with
a program for a filter,a packet size,a timeout.
This method will call the function open_live,then compile the filter string by compile(),
set the filter and returns the pointer (B<pcap_t *>).                        

=item pcapinit_offline($fname)

is a method for an offline pcap init.The input parameter is a name of the file
which contains raw output of the libpcap dump function.
Returns the pointer (B<pcap_t *>).  

=item B<ethnew>(B<$device>,B<dest> => B<ARGOFDEST>,B<source> => B<ARGOFSOURCE>)

is a method for init the ethernet subclass in the current object, B<$device> is a
required parameter,B<dest> and B<source> are an optional, B<$device> is an ethernet
device e.g. B<eth0>, an B<ARGOFDEST> and an B<ARGOFSOURCE> are a the ethernet addresses
in the ethernet header of the current object.

The B<ARGOFDEST> and the B<ARGOFSOURCE> can be given as a string which contain 
just 6 bytes of the real ethernet address or like the output of the ifconfig(8) 
e.g. 00:00:E8:43:0B:2A or just an ip address or a hostname of a target, 
then a mac address will be discovered automatically.

The ethernet frame will be sent with given addresses.
By default the B<source> and the B<dest> will be filled with a hardware address of   
the B<$device>.

B<NOTE:> For use methods which are related to the ethernet you have to before initialize
ethernet subclass by B<ethnew>. 

=item ethset

is a method for set an ethernet parameters in the current object.
The given parameters must look like parameters for the B<ethnew> without
a B<$device>.

=item ethsend

is a method for send an ethernet frame.
The given parameters must look like a parameters for the B<send>.

=item send_eth_frame($frame,$times,$delay)

is a method for send any ethernet frame which you may construct by
hands.B<$frame> is a packed ethernet frame except destination and
source fields(these fields can be setting by B<ethset> or B<ethnew>).
Another parameters must look like the parameters for the B<send>. 

=item optset(OPTPROTO => { type => [...],data => [...] },...)

is a method for set an IP and a TCP options.
The parameters for the optset must be given as a key-value pairs.  
The B<OPTPROTO>,s are the prototypes of the options(B<ip>,B<tcp>),values are the hashes
references.The keys in this hashes are B<type> and B<data>.
The value of the B<type> is an array reference.
This array must be filled with an integers.Refer to a RFC for a valid types.The value of 
the B<data> also is an array reference. This array must be filled 
with strings which must contain all bytes from a option except bytes 
with type and length of an option.Of course indexes in those arrays must be 
equal for the one option.If type is equal to 0 or 1 then there is no bytes
with a length and a data,but you have to specify zero data for compatibility.

=item B<optget>(OPTPROTO => { type => [...] },...)  

is a method for get an IP and a TCP options.
The parameters for the optget must be given as key-value pairs.
The B<OPTPROTO> is the prototype of the options(B<ip>,B<tcp>),the values are 
the hashes references.The key is the B<type>.The value of the B<type> is an array reference.
The return value is an array which will be filled with asked types,lengths,datas
of the each type of the option in order as you have asked.If you do not specify type then
all types,lengths,datas of an options will be returned.
E.g. you want to know all the IP options from the current object.
Here is a code:

@opts = $n->optget(ip => {});

E.g. you want to know just the IP options with the type which equal to 131 and 137.
Here is a code:

($t131,$l131,$d131,$t137,$l137,$d137) = $n->optget(
                                   ip =>{
                        type =>[(131,137)]
                        }        );                        

=item B<optunset>

is a method for unset a subclass of the IP or the TCP options from a current
object.It can be used if you  won't use options in the current object later.
This method must be used only after the B<optset>.
The parameters for this method are the B<OPTPROTO>'s. 
E.g. you want to unset an IP options.
Here is a code:

$n->optunset('ip');

E.g. you want to unset a TCP and an IP options.
Here is a code:

$n->optunset('ip','tcp');

=back

=head1 AUTHOR

Sergey Kolychev <ksv@al.lg.ua>

Current Maintainer: Gabor Szabo <gabor@pti.co.il>

=head1 COPYRIGHT

Copyright (c) 1998-2006 Sergey Kolychev. All rights reserved. This program is free
software; you can redistribute it and/or modify it under the same terms
as Perl itself.

=head1 CREDITS

Steve Bonds <u5rhsiz02@sneakemail.com>
  + work on some endianness bugs and improving code comments

=head1 SEE ALSO

perl(1),Net::RawIP::libpcap(3pm),tcpdump(1),RFC 791-793,RFC 768.

L<Net::Pcap>, L<Net::Pcap::Reassemble>, L<Net::PcapUtils>
L<Net::Pcap::FindDevice>

=cut

