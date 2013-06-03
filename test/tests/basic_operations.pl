@basic_operations = (
    {
        'category' => 'basic operations',
        'detail'   => 'dump config',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/SYSLOG_IDENTITY/],
        'exec_err' => $NO,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'def_access'} --dump-config",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'detail'   => 'override config',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/ENABLE_PCAP_PROMISC.*\'Y\'/],
        'exec_err' => $NO,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args " .
            "-O $conf_dir/override_fwknopd.conf --dump-config",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'show last args',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Could\snot|Last\sfwknop/i],
        'exec_err' => $IGNORE,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd --show-last",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '--get-key path validation',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/could\snot\sopen/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -a $fake_ip " .
            "-D $loopback_ip --get-key not/there",
        'fatal'    => $YES
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'require [-s|-R|-a]',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/must\suse\sone\sof/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -D $loopback_ip",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '--allow-ip <IP> valid IP',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Invalid\sallow\sIP\saddress/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -a invalidIP -D $loopback_ip",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '-A <proto>/<port> specification (proto)',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Invalid\sSPA\saccess\smessage/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A invalid/22 -a $fake_ip -D $loopback_ip",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '-A <proto>/<port> specification (port)',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Invalid\sSPA\saccess\smessage/i],
        'exec_err' => $YES,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/600001 -a $fake_ip -D $loopback_ip",
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'generate SPA packet',
        'function' => \&client_send_spa_packet,
        'cmdline'  => $default_client_args,
        'fatal'    => $YES
    },

    ### rc tests: digest
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'digest MD5',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*MD5/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'digest SHA1',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'digest SHA256',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA256'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA256/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'digest SHA384',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA384'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA384/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'digest SHA512',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA512'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA512/],
        'fatal'    => $NO
    },
    ### rc tests: spa server proto
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'spa server proto UDP',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'UDP'}}],
        'positive_output_matches' => [qr/protocol:\sudp/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'spa server proto TCP',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'TCP'}}],
        'positive_output_matches' => [qr/protocol:\stcp/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'spa server proto HTTP',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'HTTP'}}],
        'positive_output_matches' => [qr/protocol:\shttp/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'spa server proto TCPRAW',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'TCPRAW'}}],
        'positive_output_matches' => [qr/protocol:\stcpraw/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'spa server proto ICMP',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'ICMP'}}],
        'positive_output_matches' => [qr/protocol:\sicmp/],
        'fatal'    => $NO
    },
    ### rc tests: spa server port
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'spa server port 65421',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PORT' => '65421'}}],
        'positive_output_matches' => [qr/destination\sport:\s65421/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'spa server port 22',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PORT' => '22'}}],
        'positive_output_matches' => [qr/destination\sport:\s22/],
        'fatal'    => $NO
    },
    ### rc tests: spa source port
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'spa source port 65421',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SOURCE_PORT' => '65421'}}],
        'positive_output_matches' => [qr/source\sport:\s65421/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'spa source port 22',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SOURCE_PORT' => '22'}}],
        'positive_output_matches' => [qr/source\sport:\s22/],
        'fatal'    => $NO
    },
    ### rc tests: firewall timeout
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'firewall timeout 1234s',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '1234'}}],
        'positive_output_matches' => [qr/Client\sTimeout:\s1234/],
        'fatal'    => $NO
    },
    ### rc tests: hmac digest
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'HMAC digest MD5',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'MD5'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*MD5/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'HMAC digest SHA1',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA1/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'HMAC digest SHA256',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA256'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA256/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'HMAC digest SHA384',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA384'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA384/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'HMAC digest SHA512',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA512'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA512/],
        'fatal'    => $NO
    },
    ### rc file saving --save-rc-stanza
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest MD5',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --digest-type MD5",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*MD5/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest SHA1',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --digest-type SHA1",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest SHA256',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --digest-type SHA256",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA256/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest SHA384',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --digest-type SHA384",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA384/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest SHA512',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --digest-type SHA512",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA512/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'HMAC digest MD5',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --hmac-digest-type MD5",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*MD5/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'HMAC digest SHA1',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --hmac-digest-type SHA1",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'MD5'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA1/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'HMAC digest SHA256',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --hmac-digest-type SHA256",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'MD5'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA256/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'HMAC digest SHA384',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --hmac-digest-type SHA384",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'MD5'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA384/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'HMAC digest SHA512',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --hmac-digest-type SHA512",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'MD5'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA512/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'spa server proto UDP',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --server-proto UDP",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'TCP'}}],
        'positive_output_matches' => [qr/protocol:\sudp/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'spa server proto TCP',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --server-proto TCP",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'UDP'}}],
        'positive_output_matches' => [qr/protocol:\stcp/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'spa server proto HTTP',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --server-proto HTTP",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'UDP'}}],
        'positive_output_matches' => [qr/protocol:\shttp/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'spa server proto TCPRAW',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --server-proto TCPRAW",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'UDP'}}],
        'positive_output_matches' => [qr/protocol:\stcpraw/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'spa server proto ICMP',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --server-proto ICMP",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'UDP'}}],
        'positive_output_matches' => [qr/protocol:\sicmp/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'spa source port 65421',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --source-port 65421",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SOURCE_PORT' => '65531'}}],
        'positive_output_matches' => [qr/source\sport:\s65421/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'spa destination port 65421',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --server-port 65421",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PORT' => '65531'}}],
        'positive_output_matches' => [qr/destination\sport:\s65421/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'firewall timeout 1234s',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --fw-timeout 1234",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'positive_output_matches' => [qr/Client\sTimeout:\s1234/],
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'list current fwknopd fw rules',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --fw-list",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'list all current fw rules',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --fw-list-all",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'flush current firewall rules',
        'function' => \&generic_exec,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --fw-flush",
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'start',
        'function' => \&server_start,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'stop',
        'function' => \&server_stop,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'write PID',
        'function' => \&write_pid,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'fatal'    => $NO
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => '--packet-limit 1 exit',
        'function' => \&server_packet_limit,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --packet-limit 1 $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'ignore packets < min SPA len (140)',
        'function' => \&server_ignore_small_packets,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --packet-limit 1 $intf_str",
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => '-P bpf filter ignore packet',
        'function' => \&server_bpf_ignore_packet,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args --packet-limit 1 $intf_str " .
            qq|-P "udp port $non_std_spa_port"|,
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode CBC',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode CBC",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*CBC/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode ECB',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode ECB",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*ECB/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode CFB',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode CFB",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*CFB/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode PCBC (unsupported)',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode PCBC",
        'positive_output_matches' => [qr/Invalid\sencryption\smode:\sPCBC/],
        'fatal'    => $NO
    },    
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode OFB',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode OFB",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*OFB/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode CTR',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode CTR",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*CTR/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode Asymmetric',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode \"Asymmetric\"",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*Asymmetric/],
        'fatal'    => $NO
    },    
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode legacy',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode legacy",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*legacy/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'bad encryption mode',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode badmode",
        'positive_output_matches' => [qr/Invalid\sencryption\smode:\sbadmode/],
        'fatal'    => $NO
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'bad file descriptor',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --fd -1",
        'positive_output_matches' => [qr/Value\s.*out\sof\srange/],
        'fatal'    => $NO
    },
);
