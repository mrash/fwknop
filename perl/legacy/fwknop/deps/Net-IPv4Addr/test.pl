# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

use strict;
use Test;

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { plan tests => 37 }
use Net::IPv4Addr qw(/^ipv4/);


# ipv4_parse
ok( scalar ipv4_parse( "127.0.0.1" ), "127.0.0.1" );
ok( scalar ipv4_parse( "192.168.100.1 / 24" ), "192.168.100.1/24" );
ok( scalar ipv4_parse( "130.10.2.10", "255.255.255.0"), "130.10.2.10/24");
ok( scalar ipv4_parse( "130.10.2.10", "255.255.255.240"), "130.10.2.10/28");
ok( scalar ipv4_parse( "130.10.2.10/28"), "130.10.2.10/28");

# ipv4_dftl_netmask
ok( ipv4_dflt_netmask( "127.0.0.1" ), "255.0.0.0" );
ok( ipv4_dflt_netmask( "172.0.0.01" ), "255.255.0.0" );
ok( ipv4_dflt_netmask( "198.0.0.20" ), "255.255.255.0" );

# ipv4_network
ok( scalar ipv4_network( "127.0.0.1"), "127.0.0.0/8" );
ok( scalar ipv4_network( "192.168.100.10" ), "192.168.100.0/24" );
ok( scalar ipv4_network( "192.168.100.100/255.255.255.192"), "192.168.100.64/26" );

# ipv4_broadcast
ok( ipv4_broadcast( "127.0.0.1"), "127.255.255.255" );
ok( ipv4_broadcast( "192.168.100.10/24" ), "192.168.100.255" );
ok( ipv4_broadcast( "192.168.100.100/255.255.255.192"), "192.168.100.127" );

# ipv4_in_network
ok( ipv4_in_network( "127.0.0.1", "127.0.0.1" ) );
ok( not ipv4_in_network( "127.0.0.0/8", "192.168.30.1" ));
ok( not ipv4_in_network( "192.168.100.10", "192.168.100.30"));
ok( ipv4_in_network( "192.168.100.10/24", "192.168.100.255"));
ok( ipv4_in_network( "192.168.100.0/24", "192.168.100.0"));
ok( not ipv4_in_network( "192.16.100.63/26", "192.168.100.65"));
ok( ipv4_in_network( "192.168.100.0/24", "0.0.0.0" ) );
ok( ipv4_in_network( "192.168.100.0/24", "255.255.255.255" ) );
ok( ipv4_in_network( "0.0.0.0", "192.168.1.1" ) );
ok( ipv4_in_network( "255.255.255.255", "192.176.1.8" ) );
ok( ipv4_in_network( "192.168.199.0/30", "192.168.199.1" ) );
ok( ipv4_in_network( "212.117.64.0/19", "212.117.65.42/28" ) );
ok( !ipv4_in_network( "21.10.0.4/24", "0.0.0.0/0" ) );

# ipv4_cidr2msk
ok( ipv4_cidr2msk( 24 ), "255.255.255.0" );
ok( ipv4_cidr2msk( 16 ), "255.255.0.0" );
ok( ipv4_cidr2msk( 8  ), "255.0.0.0" );
ok( ipv4_cidr2msk( 26 ), "255.255.255.192" );
ok( ipv4_cidr2msk( 0 ), "0.0.0.0" );
ok( ipv4_cidr2msk( 32 ), "255.255.255.255" );

# ipv4_msk2cidr
ok( ipv4_msk2cidr( "255.255.255.0" ),  24);
ok( ipv4_msk2cidr( "255.255.0.0" ), 16 );
ok( ipv4_msk2cidr( "255.0.0.0" ), 8 );
ok( ipv4_msk2cidr( "255.255.255.192" ), 26 );
ok( ipv4_msk2cidr( "0.0.0.0" ), 0 );
ok( ipv4_msk2cidr( "255.255.255.255" ), 32 );



