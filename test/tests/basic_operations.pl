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
);
