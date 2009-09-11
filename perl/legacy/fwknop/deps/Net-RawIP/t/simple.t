#!/usr/bin/perl
use strict;
use warnings;

use Test::More;
my $tests;
plan tests => $tests;

use Data::Dumper qw(Dumper);
use English qw( -no_match_vars );

my $warn;
BEGIN {
    $SIG{__WARN__} = sub { $warn = shift; }
}
use_ok 'Net::RawIP';
BEGIN { $tests += 1; }
{
    if ($EUID) {
        like $warn, qr/Must have EUID == 0/, "root warning seen";
    } else {
        ok(not(defined $warn), "no root warning");
    }
    BEGIN { $tests += 1; }
}
$SIG{__WARN__} = 'DEFAULT';


$warn = '';
diag "Testing $Net::RawIP::VERSION";

{
    my $rawip = Net::RawIP->new;
    isa_ok($rawip, 'Net::RawIP');

    #diag Dumper $rawip;
    is($rawip->proto, 'tcp', 'default protocol is tcp');
    ok($rawip->{pack});

    isa_ok($rawip->{tcphdr}, 'Net::RawIP::tcphdr');
    # TODO: is that empty element in the end really needed?
    is_deeply($rawip->{tcphdr}, 
            [0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 65535, 0, 0, ''],
            'tcphdr is correct');
    isa_ok($rawip->{iphdr},  'Net::RawIP::iphdr');
    is_deeply($rawip->{iphdr},
        [4, 5, 16, 0, 0, 16384, 64, 6, 0, 0, 0],
        'iphdr is correct');

    #$rawip->ethnew('eth0');
    #diag Dumper $rawip;
    is_deeply([sort keys %$rawip], [qw(iphdr pack proto tcphdr)]);
    
    is($warn, '', 'no warnnigs');
    BEGIN { $tests += 9; }
}

{
    my $rawip = Net::RawIP->new({ udp => {} });
    isa_ok($rawip, 'Net::RawIP');
    
    is($rawip->proto, 'udp', 'protocol is set to udp');
    my @iphdr_result  = (4, 5, 16, 0, 0, 16384, 64, 17, 0, 0, 0);
    my @udphdr_result = (0, 0, 0, 0, '');
    
    isa_ok($rawip->{udphdr}, 'Net::RawIP::udphdr'); 
    isa_ok($rawip->{iphdr},  'Net::RawIP::iphdr'); 

    #diag Dumper $rawip;
    is_deeply($rawip->{udphdr}, \@udphdr_result);
    is_deeply($rawip->{iphdr},  \@iphdr_result);


    $rawip->set({
                ip => {
                            saddr => 3,
                            daddr => 2,
                    },
                udp => {
                            source => 55,
                            dest   => 100,
                            data   => 'payload',
                        },
                });
    @iphdr_result[9, 10] = (3, 2);
    @udphdr_result[0, 1, 4] = (55, 100, 'payload');
    is_deeply([sort keys %$rawip], [qw(iphdr pack proto udphdr)]);
    is_deeply($rawip->{udphdr}, \@udphdr_result);
    is_deeply($rawip->{iphdr},  \@iphdr_result);


    $rawip->set({ ip => { saddr => 1, }, });
    $iphdr_result[9] = 1;
    is_deeply($rawip->{udphdr}, \@udphdr_result);
    is_deeply($rawip->{iphdr},  \@iphdr_result);


    my @array = $rawip->get();
    is_deeply(\@array, [], 'empty get in list context');

    my $request = {
            ip  => [qw(tos saddr daddr)],
            tcp => [qw(psh syn urg ack rst fin)],
            udp => [qw(source dest data)],
        };
    @array = $rawip->get($request);
    is_deeply(\@array, [16, 1, 2, 55, 100, 'payload'], 'get in list context');
    #diag Dumper \@array;

    my $scalar = $rawip->get;
    is_deeply($scalar, {}, 'empty get in scalar context');
    $scalar = $rawip->get($request);
    is_deeply($scalar, {
                'tos'    => 16,
                'source' => 55,
                'saddr'  => 1,
                'daddr'  => 2,
                'dest'   => 100,
                'data'   => 'payload'
            },
            'get in scalar context');
    #diag Dumper $scalar;

    #$rawip->send(0,1);
    is($warn, '', 'no warnnigs');
    BEGIN { $tests += 16; }
}

{
    my $rawip = Net::RawIP->new({ udp => {} });
    my $pack = $rawip->optset();
    is($pack, $rawip->{pack});

    my $data = 'load12345';
    $pack = $rawip->optset(ip => {
                type => [(7)],
                data => [($data)],
                });
    is($pack, $rawip->{pack});
    isa_ok($rawip->{optsip}, 'Net::RawIP::opt');
    is_deeply($rawip->{optsip}, [[7], [11], ['load12345']]);
    is_deeply($rawip->{udphdr}, [0, 0, 0, 0, '', [7, 11, 'load12345']]);
    #diag Dumper $rawip;

    my @res = $rawip->optget(ip => {});
    is_deeply(\@res, [7, 11, 'load12345'], 'optget ip');
    #diag Dumper \@res;

    $rawip->optunset('ip');
    #diag Dumper $rawip;
    isnt(exists($rawip->{optsip}), 'optsip removed');
    is_deeply($rawip->{udphdr}, [0, 0, 0, 0, '', 0], 'udphdr reset');

    is($warn, '', 'no warnnigs');
    BEGIN { $tests += 9; }
}

{
    my $rawip = Net::RawIP->new({ icmp => {} });
    isa_ok($rawip, 'Net::RawIP');
    
    is($rawip->proto, 'icmp', 'protocol is set to icmp');
    #diag Dumper $rawip;
    my @iphdr_result  = (4, 5, 16, 0, 0, 16384, 64, 1, 0, 0, 0);
    my @icmphdr_result = (0, 0, 0, 0, 0, 0, 0, 0, '');

    isa_ok($rawip->{icmphdr}, 'Net::RawIP::icmphdr'); 
    isa_ok($rawip->{iphdr},  'Net::RawIP::iphdr'); 

    #diag Dumper $rawip;
    is_deeply($rawip->{icmphdr}, \@icmphdr_result);
    is_deeply($rawip->{iphdr},  \@iphdr_result);
    is_deeply([sort keys %$rawip], [qw(icmphdr iphdr pack proto)]);

    is($warn, '', 'no warnnigs');
    BEGIN { $tests += 8; }
}


{
    my $rawip = Net::RawIP->new({ generic => {} });
    isa_ok($rawip, 'Net::RawIP');
    
    is($rawip->proto, 'generic', 'protocol is set to generic');
    #diag Dumper $rawip;
    my @iphdr_result  = (4, 5, 16, 0, 0, 16384, 64, 0, 0, 0, 0);
    isa_ok($rawip->{generichdr}, 'Net::RawIP::generichdr'); 
    isa_ok($rawip->{iphdr},  'Net::RawIP::iphdr'); 

    #diag Dumper $rawip;
    is_deeply($rawip->{generichdr}, ['']);
    is_deeply($rawip->{iphdr},  \@iphdr_result);

    is_deeply([sort keys %$rawip], [qw(generichdr iphdr pack proto)]);
    BEGIN { $tests += 7; }
}   

{
    eval {
        Net::RawIP->new({ no_such => {} });
    };
    like($@, qr{'no_such' is not a valid key});

    eval {
        Net::RawIP->new({ generic => {}, tcp => {} });
    };
    like($@, qr{Duplicate protocols defined: 'tcp' and 'generic'});

    BEGIN { $tests += 2; }
}

# TODO: pass constructor invalid fields
# TODO: test the content of the ->{pack} variable


