@basic_operations = (
    {
        'category' => 'basic operations',
        'detail'   => 'dump config',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/SYSLOG_IDENTITY/],
        'exec_err' => $NO,
        'cmdline' => "$fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'def_access'} --dump-config",
    },
    {
        'category' => 'basic operations',
        'detail'   => 'override config',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/ENABLE_PCAP_PROMISC.*\'Y\'/],
        'exec_err' => $NO,
        'cmdline' => "$fwknopdCmd $default_server_conf_args " .
            "-O $conf_dir/override_fwknopd.conf --dump-config",
    },
    {
        'category' => 'basic operations',
        'detail'   => 'multiple override configs',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/ENABLE_PCAP_PROMISC.*\'N\'/,
            qr/FILTER.*1234/],
        'exec_err' => $NO,
        'cmdline' => "$fwknopdCmd -c $cf{'def'} -d $default_digest_file " .
            "-p $default_pid_file --dump-config " .
            "-O $conf_dir/override_fwknopd.conf,$conf_dir/override2_fwknopd.conf",
    },
    {
        'category' => 'basic operations',
        'detail'   => 'config var expansion',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/test\.pid/],
        'exec_err' => $NO,
        'cmdline' => "$fwknopdCmd -c $conf_dir/var_expansion_fwknopd.conf " .
            "-d $default_digest_file --dump-config "
    },
    {
        'category' => 'basic operations',
        'detail'   => 'invalid config var expansion',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Invalid embedded/],
        'exec_err' => $NO,
        'cmdline' => "$fwknopdCmd -c $conf_dir/var_expansion_invalid_fwknopd.conf " .
            "-d $default_digest_file --dump-config "
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'dump error codes',
        'function' => \&generic_exec,
        'exec_err' => $NO,
        'cmdline' => "$fwknopdCmd $default_server_conf_args " .
            "--dump-serv-err-codes",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'start restart stop cycle',
        'function' => \&server_start_stop_cycle,
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'show last args (1)',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Could\snot|Last\sfwknop/i],
        'exec_err' => $IGNORE,
        'cmdline' => "$fwknopCmd --show-last",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'show last args (2)',
        'function' => \&rm_last_args,
        'positive_output_matches' => [qr/Could\snot|Last\sfwknop/i],
        'exec_err' => $YES,
        'cmdline' => "$fwknopCmd --show-last",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'show last args (3)',
        'function' => \&rm_last_args,
        'positive_output_matches' => [qr/Unable\sto\sdetermine/i],
        'exec_err' => $YES,
        'cmdline' => "env -u HOME $fwknopCmd --show-last --rc-file $cf{'rc_def_key'}",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'show last args (4)',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline' => "$fwknopCmd --save-args-file empty.args " .
            "--show-last --rc-file $cf{'rc_def_key'}",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'save args too long',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip " .
            "--get-key $local_key_file --save-args-file too_long.args " . "-A tcp/22 "x300
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'previous args (1)',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/max\scommand\sline\sargs/i],
        'exec_err' => $YES,
        'cmdline' => "$fwknopCmd -l --save-args-file invalid.args",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'previous args (2)',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline' => "$fwknopCmd -l --save-args-file /dev/null",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '--get-key path validation',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/could\snot\sopen/i],
        'exec_err' => $YES,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip " .
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
        'cmdline' => "$fwknopCmd -D $loopback_ip",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '--allow-ip <IP> valid IP',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Invalid\sallow\sIP/i],
        'exec_err' => $YES,
        'cmdline' => "$fwknopCmd -A tcp/22 -a invalidIP -D $loopback_ip",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '-A <proto>/<port> specification (proto)',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Invalid\sSPA\saccess\smessage/i],
        'exec_err' => $YES,
        'cmdline' => "$fwknopCmd -A invalid/22 -a $fake_ip -D $loopback_ip",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '-A <proto>/<port> specification (port)',
        'function' => \&generic_exec,
        'positive_output_matches' => [qr/Invalid\sSPA\saccess\smessage/i],
        'exec_err' => $YES,
        'cmdline' => "$fwknopCmd -A tcp/600001 -a $fake_ip -D $loopback_ip",
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
        'subcategory' => 'client',
        'detail'   => 'SPA packet --key-rijndael',
        'function' => \&client_send_spa_packet,
        'cmdline'  => "$default_client_args_no_get_key --key-rijndael fwknoptest",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA --key-rijndael --key-len',
        'function' => \&client_send_spa_packet,
        'cmdline'  => "$default_client_args_no_get_key --key-rijndael fwknoptest --key-len 10",
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA --key-rijndael --key-hmac',
        'function' => \&client_send_spa_packet,
        'cmdline'  => "$default_client_args_no_get_key --key-rijndael " .
            "fwknoptest --key-hmac testing",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA --key-hmac --hmac-key-len',
        'function' => \&client_send_spa_packet,
        'cmdline'  => "$default_client_args_no_get_key --key-rijndael " .
            "fwknoptest --key-hmac testing --hmac-key-len 7",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA invalid --hmac-key-len',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args_no_get_key --key-rijndael " .
            "fwknoptest --key-hmac testing --hmac-key-len 999999",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA invalid --key-len',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args_no_get_key --key-rijndael " .
            "fwknoptest --key-len 999999",
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA packet --key-base64-rijndael',
        'function' => \&client_send_spa_packet,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--key-base64-rijndael Zndrbm9wdGVzdA==",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA packet base64 --key-hmac',
        'function' => \&client_send_spa_packet,
        'cmdline'  => "$default_client_args_no_get_key --key-base64-rijndael " .
            "Zndrbm9wdGVzdA== --key-base64-hmac dGVzdGluZw==",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA packet undef LOGNAME',
        'function' => \&client_send_spa_packet,
        'cmdline'  => "env -u LOGNAME $default_client_args_no_get_key --key-base64-rijndael " .
            "Zndrbm9wdGVzdA== --key-base64-hmac dGVzdGluZw==",
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'libfko',
        'detail'   => 'acquire FKO context',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'all',
        'wrapper_script'  => $wrapper_exec_script,
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_basic',
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'libfko',
        'detail'   => 'acquire FKO context (with valgrind)',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'all',
        'wrapper_script'  => $wrapper_exec_script_valgrind,
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_basic',
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA --key-base64-rijndael invalid (1)',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args_no_get_key --key-base64-rijndael a%aaaaaaaaaaa"
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA --key-base64-rijndael invalid (2)',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args_no_get_key --key-base64-rijndael " . 'QUFB'x100 ### 'A' base64 encoded
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA --key-base64-hmac invalid (1)',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--key-base64-rijndael aaaaaaaaaaaaa --key-base64-hmac a%aaaaaaa"
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'SPA --key-base64-hmac invalid (2)',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--key-base64-rijndael aaaaaaaaaaaaa --key-base64-hmac " . 'QUFB'x300 ### 'A' base64 encoded
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'invalid key file path',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip " .
                "-D $loopback_ip --get-key invalidpath --no-save-args $verbose_str"
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'invalid key file format',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip " .
                "-D $loopback_ip --get-key $invalid_key_file --no-save-args $verbose_str"
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'invalid key file format (2)',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip " .
                "-D $loopback_ip --get-key $invalid_key_file2 --no-save-args $verbose_str"
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'invalid key file format (3)',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip " .
                "-D $loopback_ip --get-key $invalid_key_file3 --no-save-args $verbose_str"
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'invalid home dir path',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "HOME=" . 'A'x1050 . " $default_client_args --stanza-list"
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'invalid rc file path stanza list',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args --rc-file invalidpath --stanza-list"
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'invalid rc file path /dev/null',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$fwknopCmd --rc-file /dev/null"
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'invalid rc file path too long',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args --rc-file " . 'A'x1030 . " --stanza-list"
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '--key-gen file path (-K) too long',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args --key-gen -K " . 'A'x1030
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'GPG missing recipient',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args_no_get_key --gpg-encryption",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'HTTP proxy proto mismatch',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args --http-proxy invalid -P udp",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'resolve HTTP proxy invalid port',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args --http-proxy http://www.cipherdyne.org:99999/cgi-bin/myip -P http",
    },

    ### rc tests
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'invalid var',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'BADVAR' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Parameter\serror/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'invalid var (2)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_rewrite_rc_args -n nondefault",
        'write_rc_file' => [
            {'name' => 'default', 'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}},
            {'name' => 'nondefault', 'vars' => {'BADKEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}
        ],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Parameter\serror/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'invalid var format',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => '#'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Invalid\sentry/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'invalid verbose val',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1',
                'VERBOSE' => 100}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Parameter\serror/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'KEY_FILE path',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY_FILE' => $local_key_file, 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Random\sValue/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'HMAC_KEY_FILE path',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY_FILE'
                    => $local_hmac_key_file, 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Random\sValue/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'invalid digest val',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Parameter\serror/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'invalid proto val',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Parameter\serror/],
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
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'firewall timeout 0s',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '0'}}],
        'positive_output_matches' => [qr/Client\sTimeout:\s0/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client rc file',
        'detail'   => 'timeout --fw-timeout 1234s',
        'function' => \&client_rc_file,
        'cmdline'  => $client_rewrite_rc_args,
        'write_rc_file' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '1234'}}],
        'positive_output_matches' => [qr/Client\sTimeout:\s1234/],
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
    },
    ### rc file saving --save-rc-stanza
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--key-rijndael',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --key-rijndael newkey",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/KEY.*newkey/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--key-hmac',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --key-hmac hmackey",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/HMAC_KEY.*hmackey/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest MD5',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --digest-type MD5",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*MD5/],
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*MD5/],
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
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*SHA1/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'non-default update',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n nondefault --digest-type SHA1",
        'save_rc_stanza' => [
            {'name' => 'default', 'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}},        ### with extraneous spaces
            {'name' => '  nondefault', 'vars' => {'KEY' => 'testtest', '  DIGEST_TYPE' => 'MD5'}}  ### with extraneous spaces
        ],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*MD5/, qr/DIGEST_TYPE.*SHA1/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'non-default update (2)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n nondefault --digest-type SHA1",
        'save_rc_stanza' => [
            {'name' => 'default', 'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}},
            {'name' => 'nondefault', 'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}},
            {'name' => 'nondefault2', 'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}
        ],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*MD5/, qr/DIGEST_TYPE.*SHA1/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'require stanza name or -D',
        'function' => \&client_rc_file,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip " .
            "--no-save-args $verbose_str --rc-file $save_rc_file --key-gen " .
            "--save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Must\suse.*destination/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'require SPA destination',
        'function' => \&client_rc_file,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip " .
            "--no-save-args $verbose_str --rc-file $save_rc_file " .
            "--save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Must\suse.*destination/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'invalid SPA destination (1)',
        'function' => \&client_rc_file,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip " .
            "--no-save-args $verbose_str -D .168.10.1 -n default " .
            "--rc-file $save_rc_file --save-rc-stanza --force-stanza",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/packet\snot\ssent/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'invalid SPA destination (2)',
        'function' => \&client_rc_file,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip " .
            "--no-save-args $verbose_str -D badhost -n default " .
            "--rc-file $save_rc_file --save-rc-stanza --force-stanza",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/packet\snot\ssent/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'invalid base64 HMAC key',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_force --key-gen -n default " .
            "--digest-type SHA1 --use-hmac",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY_BASE64' => 'testtest', 'HMAC_KEY_BASE64' => 'aaa%aaaa',
                    'DIGEST_TYPE' => 'MD5'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/look\slike\sbase64/],
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*MD5/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'invalid base64 key',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_force --key-gen -n default " .
            "--digest-type SHA1 --use-hmac",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY_BASE64' => 'tes%test', 'DIGEST_TYPE' => 'MD5'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/look\slike\sbase64/],
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*MD5/],
    },


    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest SHA1 ask (y)/n (1)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_force --key-gen -n default " .
            "--digest-type SHA1 --use-hmac",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'client_popen' => 'y',  ### interact with ask overwrite feature
        'positive_output_matches' => [qr/Updating\sparam.*SHA1/],
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*SHA1/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest SHA1 ask (y)/n (2)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_force --key-gen -n default " .
            "--digest-type SHA1 --use-hmac",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'HMAC_KEY' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'client_popen' => 'y',  ### interact with ask overwrite feature
        'positive_output_matches' => [qr/Updating\sparam.*SHA1/],
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*SHA1/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest SHA1 ask (y)/n (3)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_force --key-gen -n default " .
            "--digest-type SHA1 --use-hmac",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY_BASE64' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'client_popen' => 'y',  ### interact with ask overwrite feature
        'positive_output_matches' => [qr/Updating\sparam.*SHA1/],
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*SHA1/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest SHA1 ask (y)/n (4)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_force --key-gen -n default " .
            "--digest-type SHA1 --use-hmac",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'HMAC_KEY_BASE64' => 'testtest', 'DIGEST_TYPE' => 'MD5'}}],
        'client_popen' => 'y',  ### interact with ask overwrite feature
        'positive_output_matches' => [qr/Updating\sparam.*SHA1/],
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*SHA1/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'digest SHA1 ask y/(n) (1)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_force --key-gen -n default " .
            "--digest-type SHA1 --use-hmac",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY_BASE64' => 'dGVzdHRlc3Q=', 'DIGEST_TYPE' => 'MD5'}}],
        'client_popen' => 'n',  ### interact with ask overwrite feature
        'positive_output_matches' => [qr/Updating\sparam.*SHA1/],
        'rc_positive_output_matches' => [qr/KEY_BASE64.*dGVzdHRlc3Q=/],
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
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*SHA256/],
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
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*SHA384/],
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
        'rc_positive_output_matches' => [qr/DIGEST_TYPE.*SHA512/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--use-hmac',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args --use-hmac -n default",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/USE_HMAC.*Y/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--spoof-user',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --spoof-user someuser",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Username\:\ssomeuser/],
        'rc_positive_output_matches' => [qr/SPOOF_USER.*someuser/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--spoof-user invalid',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --spoof-user some=user",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Args\scontain\sinvalid/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--spoof-source 3.3.3.3',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -P udpraw --spoof-source 3.3.3.3",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/SPOOF_SOURCE_IP.*3.3.3.3/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--spoof-source invalid',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -P udpraw --spoof-source invalid",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1',
                    'SPOOF_SOURCE_IP' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Invalid\sspoof/],
        'rc_positive_output_matches' => [qr/SPOOF_SOURCE_IP.*invalid/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--spoof-source invalid -P',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -P invalid --spoof-source 3.3.3.3",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1',
                    'SPOOF_SOURCE_IP' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Unrecognized\sproto/],
        'rc_positive_output_matches' => [qr/SPOOF_SOURCE_IP.*invalid/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--spoof-src.. invalid -P',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -P tcp --spoof-source 3.3.3.3",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1',
                    'SPOOF_SOURCE_IP' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Must\sset.*udpraw/],
        'rc_positive_output_matches' => [qr/SPOOF_SOURCE_IP.*invalid/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '-r rand port',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -r",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA1/, qr/destination\sport\:\s(?!62201)/],
        'rc_positive_output_matches' => [qr/RAND_PORT.*Y/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--nat-local',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --nat-local",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1', 'NAT_LOCAL' => 'Y'}}],
        'positive_output_matches' => [qr/Nat\sAccess\:\s127.0.0.1\,22/],
        'rc_positive_output_matches' => [qr/NAT_LOCAL.*Y/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--nat-local -f 1234',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --nat-local --fw-timeout 1234",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1', 'NAT_LOCAL' => 'Y',
                    'FW_TIMEOUT' => '1111'}}],
        'positive_output_matches' => [qr/Nat\sAccess\:\s127.0.0.1\,22/],
        'rc_positive_output_matches' => [qr/NAT_LOCAL.*Y/, qr/FW_TIMEOUT.*1234/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--nat 192.168.10.1:12345',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -N 192.168.10.1:12345",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Nat\sAccess\:\s192.168.10.1\,12345/],
        'rc_positive_output_matches' => [qr/NAT_ACCESS.*192.168.10.1\:12345/],
    },
#    {
#        'category' => 'basic operations',
#        'subcategory' => 'client save rc file',
#        'detail'   => '--nat 192.168.10.1:99999',
#        'function' => \&client_rc_file,
#        'cmdline'  => "$client_save_rc_args -n default -N 192.168.10.1:99999",
#        'save_rc_stanza' => [{'name' => 'default',
#                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
#                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
#        'positive_output_matches' => [qr/Nat\sAccess\:\s192.168.10.1\,12345/],
#        'rc_positive_output_matches' => [qr/NAT_ACCESS.*192.168.10.1\:12345/],
#    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--nat client timeout 1234s',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -N 192.168.10.1:12345 -f 1234",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1',
                    'FW_TIMEOUT' => '1111'}}],
        'positive_output_matches' => [qr/Nat\sAccess\:\s192.168.10.1\,12345/],
        'rc_positive_output_matches' => [qr/NAT_ACCESS.*192.168.10.1\:12345/,
                                        qr/FW_TIMEOUT.*1234/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--nat client timeout 0s',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -N 192.168.10.1:12345 -f 0",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1',
                    'FW_TIMEOUT' => '0'}}],
        'positive_output_matches' => [qr/Nat\sAccess\:\s192.168.10.1\,12345/],
        'rc_positive_output_matches' => [qr/NAT_ACCESS.*192.168.10.1\:12345/,
                                        qr/FW_TIMEOUT.*0/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--nat-rand-port',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -N 192.168.10.1:12345 --nat-rand-port",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                'HMAC_DIGEST_TYPE' => 'SHA1', 'NAT_RAND_PORT' => '0',
                'NAT_ACCESS' => '192.168.10.1:33333'}}],
        'positive_output_matches' => [qr/Nat\sAccess\:\s192.168.10.1\,12345/],
        'rc_positive_output_matches' => [qr/NAT_ACCESS.*192.168.10.1\:12345/, qr/NAT_RAND_PORT.*Y/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--nat-port 22211',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -N 192.168.10.1:12345 --nat-port 22211",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1', 'NAT_PORT' => '11111'}}],
        'positive_output_matches' => [qr/Nat\sAccess\:\s192.168.10.1\,12345/, qr/Message.*22211/],
        'rc_positive_output_matches' => [qr/NAT_ACCESS.*192.168.10.1\:12345/, qr/NAT_PORT.*22211/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'NAT invalid access (1)',
        'function' => \&client_rc_file,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp -a $fake_ip " .
                "-D $loopback_ip --rc-file $save_rc_file --save-rc-stanza " .
                "--force-stanza --test -n default -N 192.168.10.1:12345 --nat-port 22211",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1', 'NAT_PORT' => '11111'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Expecting.*A\sarg/]
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'NAT invalid access (2)',
        'function' => \&client_rc_file,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -a $fake_ip " .
                "-D $loopback_ip --rc-file $save_rc_file --save-rc-stanza " .
                "--force-stanza --test -n default -N 192.168.10.1:12345 --nat-port 22211",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1', 'NAT_PORT' => '11111'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Invalid\sSPA\saccess/]
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'NAT invalid access (3)',
        'function' => \&client_rc_file,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/22 -a $fake_ip " .
                "-D $loopback_ip --rc-file $save_rc_file --save-rc-stanza " .
                "--force-stanza --test -n default -N .168.10.1 --nat-port 22211",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1', 'NAT_PORT' => '11111'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Unable\sto\sresolve/]
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'NAT invalid access (4)',
        'function' => \&client_rc_file,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/99999 -a $fake_ip " .
                "-D $loopback_ip --rc-file $save_rc_file --save-rc-stanza " .
                "--force-stanza --test -n default -N 192.168.10.1:99999 --nat-port 22211",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1', 'NAT_PORT' => '11111'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Invalid\sport/]
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'NAT invalid access (5)',
        'function' => \&client_rc_file,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp -a $fake_ip " .
                "-D $loopback_ip --rc-file $save_rc_file --save-rc-stanza " .
                "--force-stanza --test -n default -N 192.168.10.1:12345",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Invalid\sSPA\saccess\smessage/]
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'NAT invalid multi-port -A',
        'function' => \&client_rc_file,
        'cmdline'  => "$lib_view_str $valgrind_str $fwknopCmd -A tcp/22,tcp/123 -a $fake_ip " .
                "-D $loopback_ip --rc-file $save_rc_file --save-rc-stanza " .
                "--force-stanza --test -n default -N 192.168.10.1:12345 --nat-port 22211",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1', 'NAT_PORT' => '11111'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/NAT\sfor\smultiple/]
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'save pkt to file',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -s -B run/spa.pkt",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'ALLOW_IP' => 'source'}}],
        'positive_output_matches' => [qr/Message.*0.0.0.0/],
        'rc_positive_output_matches' => [qr/ALLOW_IP.*0.0.0.0/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'save pkt to file (append)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -s -b -B run/spa.pkt",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'ALLOW_IP' => 'source'}}],
        'positive_output_matches' => [qr/Message.*0.0.0.0/],
        'rc_positive_output_matches' => [qr/ALLOW_IP.*0.0.0.0/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'allow source',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -s",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'ALLOW_IP' => 'source'}}],
        'positive_output_matches' => [qr/Message.*0.0.0.0/],
        'rc_positive_output_matches' => [qr/ALLOW_IP.*0.0.0.0/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '-R resolve -u user agent',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -R -u FwknopTestSuite/2.6",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Resolved/],
        'rc_positive_output_matches' => [qr/RESOLVE_IP_HTTP.*Y/, qr/HTTP_USER_AGENT.*FwknopTestSuite\/2.6/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '-R resolve http (1)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -R --resolve-url http://www.cipherdyne.org/cgi-bin/myip",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Resolved/],
        'rc_positive_output_matches' => [qr/RESOLVE_IP_HTTP.*Y/, qr/RESOLVE_URL.*cipherdyne.org.*myip/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '-R resolve http (2)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -R --resolve-url www.cipherdyne.org/cgi-bin/myip",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Resolved/],
        'rc_positive_output_matches' => [qr/RESOLVE_IP_HTTP.*Y/, qr/RESOLVE_URL.*cipherdyne.org.*myip/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '-R resolve http (3)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -R --resolve-url http://127.0.0.1//",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Invalid\sIP/],
        'rc_positive_output_matches' => [qr/RESOLVE_IP_HTTP.*Y/, qr/RESOLVE_URL.*127.0.0.1/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '-R resolve http (4)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -R --resolve-url http://127.0.0.1",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Invalid\sIP/],
        'rc_positive_output_matches' => [qr/RESOLVE_IP_HTTP.*Y/, qr/RESOLVE_URL.*127.0.0.1/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '-R resolve invalid url (1)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -R --resolve-url http://127.0.0.1" . '1'x300 . '/test.cgi',
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Error\sparsing/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '-R resolve invalid url (2)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default -R --resolve-url http://127.0.0.1/" . 'A'x1200,
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Error\sparsing/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--get-key',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --get-key somefile",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/KEY.*somefile/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'key file too long',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --get-key " . 'A'x1030,
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'DIGEST_TYPE' => 'SHA1'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Could\snot\sopen/],
        'rc_positive_output_matches' => [qr/VERBOSE.*2/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--get-hmac-key',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --get-hmac-key somefile",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'HMAC_KEY' => 'hmactest',
                    'HMAC_DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/HMAC\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/KEY.*somefile/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'HMAC key file too long',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --get-hmac-key " . 'A'x1030,
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Could\snot\sopen/],
        'rc_positive_output_matches' => [qr/VERBOSE.*2/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--time-offset-plus 1M',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --time-offset-plus 1M",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/TIME_OFFSET.*60/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'time offset invalid (1)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --time-offset-plus invalid",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1',
                'TIME_OFFSET' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Parameter\serror/],
        'rc_positive_output_matches' => [qr/TIME_OFFSET.*invalid/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'time offset invalid (2)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --time-offset-plus 123456789999",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1',
                'TIME_OFFSET' => '123456789999'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Parameter\serror/],
        'rc_positive_output_matches' => [qr/TIME_OFFSET.*123456789999/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--time-offset-plus 1H',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --time-offset-plus 1H",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/TIME_OFFSET.*3600/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--time-offset-plus 1D',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --time-offset-plus 1D",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/TIME_OFFSET.*86400/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--time-offset-minus 1M',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --time-offset-minus 1M",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/TIME_OFFSET.*\-60/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'encryption mode legacy',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --encryption-mode legacy",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/ENCRYPTION_MODE.*legacy/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'encryption mode legacy (2)',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --encryption-mode legacy",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1',
                'ENCRYPTION_MODE' => 'legacy', 'USE_HMAC' => 'Y'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/incompatible\swith\sHMAC/],
        'rc_positive_output_matches' => [qr/ENCRYPTION_MODE.*legacy/],
    },


    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--encryption-mode invalid',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --encryption-mode invalid",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1',
                'ENCRYPTION_MODE' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Parameter\serror/],
        'rc_positive_output_matches' => [qr/ENCRYPTION_MODE.*invalid/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--encryption-mode CBC',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --encryption-mode CBC",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'DIGEST_TYPE' => 'SHA1'}}],
        'positive_output_matches' => [qr/Digest\sType\:\s.*SHA1/],
        'rc_positive_output_matches' => [qr/ENCRYPTION_MODE.*CBC/],
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
        'rc_positive_output_matches' => [qr/HMAC_DIGEST_TYPE.*MD5/, qr/USE_HMAC.*Y/],
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
        'rc_positive_output_matches' => [qr/HMAC_DIGEST_TYPE.*SHA1/],
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
        'rc_positive_output_matches' => [qr/HMAC_DIGEST_TYPE.*SHA256/],
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
        'rc_positive_output_matches' => [qr/HMAC_DIGEST_TYPE.*SHA384/],
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
        'rc_positive_output_matches' => [qr/HMAC_DIGEST_TYPE.*SHA512/],
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
        'rc_positive_output_matches' => [qr/SPA_SERVER_PROTO.*udp/],
        'rc_negative_output_matches' => [qr/USE_HMAC/],
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
        'rc_positive_output_matches' => [qr/SPA_SERVER_PROTO.*tcp/],
        'rc_negative_output_matches' => [qr/USE_HMAC/],
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
        'rc_positive_output_matches' => [qr/SPA_SERVER_PROTO.*http/],
        'rc_negative_output_matches' => [qr/USE_HMAC/],
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
        'rc_positive_output_matches' => [qr/SPA_SERVER_PROTO.*tcpraw/],
        'rc_negative_output_matches' => [qr/USE_HMAC/],
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
        'rc_positive_output_matches' => [qr/SPA_SERVER_PROTO.*icmp/],
        'rc_negative_output_matches' => [qr/USE_HMAC/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'invalid ICMP type',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --server-proto ICMP --icmp-type 9999",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'UDP'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Invalid\sicmp/],
        'rc_positive_output_matches' => [qr/SPA_SERVER_PROTO.*UDP/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'invalid ICMP code',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args -n default --server-proto ICMP --icmp-code 9999",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'SPA_SERVER_PROTO' => 'UDP'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Invalid\sicmp/],
        'rc_positive_output_matches' => [qr/SPA_SERVER_PROTO.*UDP/],
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
        'rc_positive_output_matches' => [qr/SPA_SOURCE_PORT.*65421/],
        'rc_negative_output_matches' => [qr/USE_HMAC/],
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
        'rc_positive_output_matches' => [qr/SPA_SERVER_PORT.*65421/],
        'rc_negative_output_matches' => [qr/USE_HMAC/],
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
        'rc_positive_output_matches' => [qr/FW_TIMEOUT.*1234/],
        'rc_negative_output_matches' => [qr/USE_HMAC/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--verbose',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_verbose -n default --fw-timeout 1234 --verbose",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'positive_output_matches' => [qr/Client\sTimeout:\s1234/],
        'rc_positive_output_matches' => [qr/VERBOSE.*Y/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => $verbose_str,
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_verbose -n default " .
            "--fw-timeout 1234 $verbose_str",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'positive_output_matches' => [qr/Client\sTimeout:\s1234/],
        'rc_positive_output_matches' => [qr/VERBOSE.*2/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'no --verbose',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_verbose -n default " .
            "--fw-timeout 1234",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'positive_output_matches' => [qr/Client\sTimeout:\s1234/],
        'rc_negative_output_matches' => [qr/VERBOSE/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--use-hmac --key-gen',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_verbose -n default " .
            "--fw-timeout 1234 $verbose_str --use-hmac --key-gen",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'positive_output_matches' => [qr/Wrote.*HMAC.*keys/],
        'rc_positive_output_matches' => [qr/VERBOSE.*(Y|\d)/,
            qr/USE_HMAC.*Y/, qr/KEY_BASE64/, qr/HMAC_KEY_BASE64/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--key-gen HMAC MD5',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_verbose -n default " .
            "--fw-timeout 1234 $verbose_str --use-hmac --key-gen --hmac-digest-type MD5",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'positive_output_matches' => [qr/Wrote.*HMAC.*keys/],
        'rc_positive_output_matches' => [qr/VERBOSE.*(Y|\d)/,
            qr/USE_HMAC.*Y/, qr/KEY_BASE64/, qr/HMAC_KEY_BASE64/,
            qr/HMAC_DIGEST_TYPE.*MD5/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--key-gen HMAC SHA1',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_verbose -n default " .
            "--fw-timeout 1234 $verbose_str --use-hmac --key-gen --hmac-digest-type SHA1",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'positive_output_matches' => [qr/Wrote.*HMAC.*keys/],
        'rc_positive_output_matches' => [qr/VERBOSE.*(Y|\d)/,
            qr/USE_HMAC.*Y/, qr/KEY_BASE64/, qr/HMAC_KEY_BASE64/,
            qr/HMAC_DIGEST_TYPE.*SHA1/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--key-gen HMAC SHA256',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_verbose -n default " .
            "--fw-timeout 1234 $verbose_str --use-hmac --key-gen --hmac-digest-type SHA256",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'positive_output_matches' => [qr/Wrote.*HMAC.*keys/],
        'rc_positive_output_matches' => [qr/VERBOSE.*(Y|\d)/,
            qr/USE_HMAC.*Y/, qr/KEY_BASE64/, qr/HMAC_KEY_BASE64/,
            qr/HMAC_DIGEST_TYPE.*SHA256/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--key-gen HMAC SHA384',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_verbose -n default " .
            "--fw-timeout 1234 $verbose_str --use-hmac --key-gen --hmac-digest-type SHA384",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'positive_output_matches' => [qr/Wrote.*HMAC.*keys/],
        'rc_positive_output_matches' => [qr/VERBOSE.*(Y|\d)/,
            qr/USE_HMAC.*Y/, qr/KEY_BASE64/, qr/HMAC_KEY_BASE64/,
            qr/HMAC_DIGEST_TYPE.*SHA384/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--key-gen HMAC SHA512',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_verbose -n default " .
            "--fw-timeout 1234 $verbose_str --use-hmac --key-gen --hmac-digest-type SHA512",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'positive_output_matches' => [qr/Wrote.*HMAC.*keys/],
        'rc_positive_output_matches' => [qr/VERBOSE.*(Y|\d)/,
            qr/USE_HMAC.*Y/, qr/KEY_BASE64/, qr/HMAC_KEY_BASE64/,
            qr/HMAC_DIGEST_TYPE.*SHA512/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => '--key-gen HMAC invalid',
        'function' => \&client_rc_file,
        'cmdline'  => "$client_save_rc_args_no_verbose -n default " .
            "--fw-timeout 1234 $verbose_str --use-hmac --key-gen --hmac-digest-type invalid",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30'}}],
        'exec_err' => $YES,
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'GPG use agent',
        'function' => \&client_rc_file,
        'cmdline'  => "$default_client_gpg_args_same_key_signer --gpg-encryption "
            . "--gpg-agent --gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw "
            . "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30',
                'GPG_HOMEDIR' => 'somepath', 'USE_GPG_AGENT' => 'Y', 'GPG_SIGNER' => 'invalid'}}],
        'positive_output_matches' => [qr/GPG sig verify/],
        'rc_positive_output_matches' => [qr/GPG_SIGNER/, qr/GPG_RECIPIENT/,
                            qr/GPG_HOMEDIR/]
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'GPG same signing key (1)',
        'function' => \&client_rc_file,
        'cmdline'  => "$default_client_gpg_args_same_key_signer --gpg-encryption "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw "
            . "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30',
                'GPG_HOMEDIR' => 'somepath', 'GPG_SIGNER' => 'invalid'}}],
        'positive_output_matches' => [qr/GPG sig verify/],
        'rc_positive_output_matches' => [qr/GPG_SIGNER/, qr/GPG_RECIPIENT/,
                            qr/GPG_HOMEDIR/]
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'GPG same signing key (2)',
        'function' => \&client_rc_file,
        'cmdline'  => "$default_client_gpg_args_same_key_signer --gpg-encryption "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw "
            . "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30',
                'GPG_HOMEDIR' => 'somepath', 'GPG_SIGNER' => 'invalid',
                'GPG_AGENT' => 'N'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Parameter\serror/],
        'rc_positive_output_matches' => [qr/GPG_SIGNER/, qr/GPG_HOMEDIR/]
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'GPG same signing key (3)',
        'function' => \&client_rc_file,
        'cmdline'  => "$default_client_gpg_args_same_key_signer --gpg-encryption "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw "
            . "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30',
                'GPG_HOMEDIR' => 'somepath', 'GPG_SIGNER' => 'invalid',
                'USE_GPG_AGENT' => 'N', 'GPG_NO_SIGNING_PW' => 'Y'}}],
        'positive_output_matches' => [qr/GPG sig verify/],
        'rc_positive_output_matches' => [qr/GPG_SIGNER/, qr/GPG_HOMEDIR/]
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'GPG invalid sign pw',
        'function' => \&client_rc_file,
        'cmdline'  => "$default_client_gpg_args_same_key_signer "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw "
            . "--gpg-exe invalidpath "
            . "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30',
                'GPG_HOMEDIR' => 'somepath', 'GPG_SIGNING_PW_BASE64' => 'aaa%aaa'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Parameter\serror/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'GPG invalid exe',
        'function' => \&client_rc_file,
        'cmdline'  => "$default_client_gpg_args_same_key_signer "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw "
            . "--gpg-exe invalidpath "
            . "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30',
                'GPG_HOMEDIR' => 'somepath', 'GPG_SIGNER' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Unable\sto\sstat/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'GPG invalid homedir',
        'function' => \&client_rc_file,
        'cmdline'  => "$default_client_gpg_args_same_key_signer "
            . "--gpg-home-dir invalidpath --gpg-no-signing-pw "
            . "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30',
                'GPG_HOMEDIR' => 'somepath', 'GPG_SIGNER' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/Unable\sto\sstat/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'GPG invalid recip',
        'function' => \&client_rc_file,
        'cmdline'  => "$default_client_args "
            . "--gpg-recipient-key invalid --gpg-signer-key $gpg_client_key "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw "
            . "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30',
                'GPG_HOMEDIR' => 'somepath', 'GPG_SIGNER' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/key\sfor.*not\sfound/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'GPG invalid signer',
        'function' => \&client_rc_file,
        'cmdline'  => "$default_client_args "
            . "--gpg-recipient-key $gpg_client_key --gpg-signer-key invalid "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw "
            . "--rc-file $save_rc_file --save-rc-stanza --force-stanza --test",
        'save_rc_stanza' => [{'name' => 'default',
                'vars' => {'KEY' => 'testtest', 'FW_TIMEOUT' => '30',
                'GPG_HOMEDIR' => 'somepath', 'GPG_SIGNER' => 'invalid'}}],
        'exec_err' => $YES,
        'positive_output_matches' => [qr/key\sfor.*not\sfound/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client save rc file',
        'detail'   => 'GPG signer pw fd 0',
        'function' => \&generic_exec,
        'cmdline'  => "echo test | $default_client_args_no_get_key "
            . "--gpg-recipient-key $gpg_client_key --gpg-signer-key $gpg_client_key "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --fd 0 --test",
        'positive_output_matches' => [qr/sig\sID/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'list current fwknopd fw rules',
        'function' => \&generic_exec,
        'cmdline' => "$fwknopdCmd $default_server_conf_args --fw-list",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'list current fw rules (2)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$server_rewrite_conf_files --fw-list",
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE any',
            'KEY    testtest'
        ],
        'server_conf_file' => [
            'FWKNOP_RUN_DIR      ' . cwd() . "/$run_tmp_dir"  ### test coverage for mkdir
        ],
        'positive_output_matches' => [qr/to\screate/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'list all current fw rules',
        'function' => \&generic_exec,
        'cmdline' => "$fwknopdCmd $default_server_conf_args --fw-list-all",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'flush current firewall rules',
        'function' => \&generic_exec,
        'cmdline' => "$fwknopdCmd $default_server_conf_args --fw-flush",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid pcap filter',
        'function' => \&generic_exec,
        'cmdline' => "$fwknopdCmd $default_server_conf_args -f -P proto invalid",
        'exec_err' => $YES,
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'digest cache validation',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'def_access'} " .
            "-p $default_pid_file $intf_str --exit-parse-config " .
            "-d $rewrite_digest_file -v -v -v -v",
        'exec_err' => $YES,
        'digest_cache_file' => [
            'ybbYzHw4QMLd3rAlifxSAIedifnchUyuU0NW02hC6Zs 17 127.0.0.1 37246 127.0.0.1 62201 1399089310',
            'rrrrrrrrU369w8emmAyP4NMx9CvgkvplpfRt1306fns 17 -127.0.0.1 58901 127.0.0.1 62201 1399089319',
            'ttttttttU369w8emmAyP4NMx9CvgkvplpfRt1306fns 17 -127..0.1 58901 127.0.0.1 62201 1399089319',
            'kVpIRhGJU369w8emmAyP4NMx9CvgkvplpfRt1306fns 17 127.0.0.1 58901 127. 62201 1399089319',
            'cXzry4ouzEAymxSRaUqTcRNniIMRCXOn7OhNMps0Bag 17',
            'YuoJRQDtKF7EdnA8JGCsVa5YsLu1az/oPeBTJ7J6Qws 17 127.0.0.1 36767 127.0.0.1 62201 1399089338'
        ],
        'positive_output_matches' => [qr/invalid\sdigest\sfile\sentry/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid -C packet count',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        ### add a few additional command line args for test coverage
        'cmdline' => "$fwknopdCmd $default_server_conf_args -f " .
            "-l somelocale --pcap-any-direction --syslog-enable -C 999999999999",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid locale',
        'function' => \&generic_exec,
        'exec_err' => $NO,
        'cmdline' => "$fwknopdCmd $default_server_conf_args -f " .
            "-l somelocale --dump-config",
        'positive_output_matches' => [qr/Unable to set locale/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid run dir path',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline' => "$fwknopdCmd -c $cf{'invalid_run_dir_path'} " .
            "-a $cf{'def_access'} -f --dump-config",
        'positive_output_matches' => [qr/is not absolute/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'sniff invalid interface',
        'function' => \&server_conf_files,
        'exec_err' => $YES,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -i invalidintf -f",
        'positive_output_matches' => [qr/pcap_open_live.*error/],
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'ENABLE_PCAP_PROMISC       Y'
        ],
    },

    ### test syslog config
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'syslog LOG_DAEMON',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -D",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'SYSLOG_FACILITY        LOG_DAEMON',
        ],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'syslog LOG_LOCAL0',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -D",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'SYSLOG_FACILITY        LOG_LOCAL0',
        ],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'syslog LOG_LOCAL1',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -D",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'SYSLOG_FACILITY        LOG_LOCAL1',
        ],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'syslog LOG_LOCAL2',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -D",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'SYSLOG_FACILITY        LOG_LOCAL2',
        ],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'syslog LOG_LOCAL3',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -D",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'SYSLOG_FACILITY        LOG_LOCAL3',
        ],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'syslog LOG_LOCAL4',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -D",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'SYSLOG_FACILITY        LOG_LOCAL4',
        ],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'syslog LOG_LOCAL5',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -D",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'SYSLOG_FACILITY        LOG_LOCAL5',
        ],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'syslog LOG_LOCAL6',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -D",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'SYSLOG_FACILITY        LOG_LOCAL6',
        ],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'syslog LOG_LOCAL7',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -D",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'SYSLOG_FACILITY        LOG_LOCAL7',
        ],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'syslog LOG_LOCAL8',
        'function' => \&server_conf_files,
        'exec_err' => $YES,
        'fwknopd_cmdline' => "$lib_view_str $valgrind_str $fwknopdCmd " .
                "-c $rewrite_fwknopd_conf -a $rewrite_access_conf " .
                "-d $default_digest_file -p $default_pid_file -D --syslog-enable",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'SYSLOG_FACILITY        LOG_LOCAL8',
        ],
        'positive_output_matches' => [qr/Invalid SYSLOG_FACILITY/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'mutually exclusive -K and -R',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        ### add a few additional command line args for test coverage
        'cmdline' => "$fwknopdCmd $default_server_conf_args -f -K -R"
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'mutually exclusive -D and -R',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        ### add a few additional command line args for test coverage
        'cmdline' => "$fwknopdCmd $default_server_conf_args -f -D -R"
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid config file path',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline' => "$fwknopdCmd -f -c invalid",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid access.conf file path',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline' => "$fwknopdCmd -f -a invalid",
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'GPG invalid --gpg-home-dir path',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline' => "$fwknopdCmd $default_server_conf_args -f --gpg-home-dir invalidpath",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'GPG invalid --gpg-home-dir path (2)',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline' => "$fwknopdCmd $default_server_conf_args -f --gpg-home-dir " . 'A'x1200
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'GPG require sig ID or fingerprint',
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'gpg_no_pw_no_fpr_access'} " .
            "-d $default_digest_file -p $default_pid_file -f",
        'positive_output_matches' => [qr/Must have either sig/],
    },


    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'start',
        'function' => \&server_start,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_conf_args $intf_str",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'stop',
        'function' => \&server_stop,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_conf_args $intf_str",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'write PID',
        'function' => \&write_pid,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_conf_args $intf_str",
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => '--packet-limit 1 exit',
        'function' => \&server_packet_limit,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_conf_args --packet-limit 1 $intf_str",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'ignore packets < min SPA len (140)',
        'function' => \&server_ignore_small_packets,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_conf_args --packet-limit 1 $intf_str",
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => '-P bpf filter ignore packet',
        'function' => \&server_bpf_ignore_packet,
        'cmdline'  => $default_client_args,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_conf_args --packet-limit 1 $intf_str " .
            qq|-P "udp port $non_std_spa_port"|,
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables INPUT spec',
        'function' => \&generic_exec,
        'cmdline' => "$fwknopdCmd -c $cf{'invalid_ipt_input_chain'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'function' => \&generic_exec,
        'exec_err' => $YES,
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables INPUT spec (2)',
        'function' => \&generic_exec,
        'cmdline' => "$fwknopdCmd -c $cf{'invalid_ipt_input_chain2'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'function' => \&generic_exec,
        'exec_err' => $YES,
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables INPUT spec (3)',
        'function' => \&generic_exec,
        'cmdline' => "$fwknopdCmd -c $cf{'invalid_ipt_input_chain3'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'function' => \&generic_exec,
        'exec_err' => $YES,
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables INPUT spec (4)',
        'function' => \&generic_exec,
        'cmdline' => "$fwknopdCmd -c $cf{'invalid_ipt_input_chain4'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'function' => \&generic_exec,
        'exec_err' => $YES,
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables INPUT spec (5)',
        'function' => \&generic_exec,
        'cmdline' => "$fwknopdCmd -c $cf{'invalid_ipt_input_chain5'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'function' => \&generic_exec,
        'exec_err' => $YES,
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables INPUT spec (6)',
        'function' => \&generic_exec,
        'cmdline' => "$fwknopdCmd -c $cf{'invalid_ipt_input_chain6'} -a $cf{'def_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'function' => \&generic_exec,
        'exec_err' => $YES,
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid pcap dispatch count',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE any',
            'KEY    testtest',
        ],
        'server_conf_file' => [
            'PCAP_DISPATCH_COUNT        9999999999'
        ],
        'positive_output_matches' => [qr/invalid\sPCAP_DISPATCH_COUNT/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'no access SOURCE',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            '  DUMMY   fdsafds#'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/not\sfind.*SOURCE/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid config line format',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$server_rewrite_conf_files --exit-parse-config",
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'PCAP_FILTER'
        ],
        'positive_output_matches' => [qr/Invalid\sconfig\sfile\sentry/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'variable substitution',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$server_rewrite_conf_files --exit-parse-config",
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'PCAP_FILTER       $NOVAR proto test'
        ],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'locale setting',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => "$server_rewrite_conf_files --exit-parse-config",
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'LOCALE     C'
        ],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid VERBOSE var setting',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'VERBOSE     -1'
        ],
        'positive_output_matches' => [qr/not\sin\sthe\srange/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => '__CHANGEME__ key (1)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        __CHANGEME__'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/KEY\s.*not\sproperly/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => '__CHANGEME__ key (2)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE      any',
            'KEY_BASE64  __CHANGEME__'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/KEY_BASE64\s.*not\sproperly/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'non-base64 key',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE      any',
            'KEY_BASE64  %%%%%%%%%%%%%'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/look\slike\sbase64/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'HMAC key __CHANGEME__ (1)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE      any',
            'KEY         testtest',
            'HMAC_KEY    __CHANGEME__'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/KEY\s.*not\sproperly/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'HMAC key __CHANGEME__ (2)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE             any',
            'KEY                testtest',
            'HMAC_KEY_BASE64    __CHANGEME__'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/KEY_BASE64\s.*not\sproperly/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'HMAC non-base64 key',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE      any',
            'KEY         testtest',
            'HMAC_KEY_BASE64  %%%%%%%%%%%%%'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/look\slike\sbase64/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'GPG key __CHANGEME__',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE                         any',
            'REQUIRE_SOURCE                 Y',
            'KEY                            testtest',
            'GPG_REQUIRE_SIG                Y',  ### additional test coverage
            'GPG_DISABLE_SIG                N',
            'GPG_IGNORE_SIG_VERIFY_ERROR    N',
            'GPG_DECRYPT_PW                 __CHANGEME__'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/PW\s.*not\sproperly/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'GPG pw != HMAC key',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE                         any',
            'HMAC_KEY                       testtest',
            'GPG_DECRYPT_PW                 testtest'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/encryption\spassphrase/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid FW_ACCESS_TIMEOUT',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE                 any',
            'KEY                    testtest',
            'FW_ACCESS_TIMEOUT      999999999999'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/not\sin\srange/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid ENCRYPTION_MODE',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE                 any',
            'KEY                    testtest',
            'ENCRYPTION_MODE        invalid'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/Unrecognized.*MODE/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid CMD_EXEC_USER',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE                 any',
            'KEY                    testtest',
            'CMD_EXEC_USER          invalid'
        ],
        'server_conf_file' => [
            '### comment'
        ],
        'positive_output_matches' => [qr/Unable.*UID/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables IPT_FORWARD_ACCESS',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'IPT_FORWARD_ACCESS     invalid'
        ],
        'positive_output_matches' => [qr/ACCESS\sspecification/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables IPT_DNAT_ACCESS',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'IPT_DNAT_ACCESS     invalid'
        ],
        'positive_output_matches' => [qr/ACCESS\sspecification/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables IPT_SNAT_ACCESS',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'IPT_SNAT_ACCESS     invalid'
        ],
        'positive_output_matches' => [qr/ACCESS\sspecification/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables IPT_SNAT_TRANSLATE_IP',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'ENABLE_IPT_FORWARDING     Y',
            'ENABLE_IPT_SNAT           Y',
            'SNAT_TRANSLATE_IP         invalid'
        ],
        'positive_output_matches' => [qr/Invalid\sIPv4/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables IPT_MASQUERADE_ACCESS',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'IPT_MASQUERADE_ACCESS     invalid'
        ],
        'positive_output_matches' => [qr/ACCESS\sspecification/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid iptables IPT_OUTPUT_ACCESS',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'IPT_OUTPUT_ACCESS     invalid'
        ],
        'positive_output_matches' => [qr/ACCESS\sspecification/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'invalid PCAP_LOOP_SLEEP',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     any',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            'PCAP_LOOP_SLEEP     9999999999999'
        ],
        'positive_output_matches' => [qr/not\sin\sthe\srange/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'access SOURCE format (1)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     1.1.1.1/aaaaaaaaaaaaaaaaaaaaa',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/Invalid\sIP\smask/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'access SOURCE format (2)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     aaaaaaaaaaaaaaaaaaaaa',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/Error\sparsing.*IP/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'access SOURCE format (3)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     123.123.123.123/255.255.255.258',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/error\sparsing.*IP/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'access SOURCE format (4)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     123.123.123.123/33',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/Invalid\sIP\smask/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'access SOURCE format (5)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     1.1.1.1/1234.1.1.1',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/error\sparsing.*IP/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'access SOURCE format (6)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     1.1.1.1/255.255.255.0, 2.2.2.2/33, 123.123.123.123/24',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/Invalid\sIP\smask/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'access SOURCE format (7)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     1.1.1.1/',
            'KEY        testtest'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/Missing\smask/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'OPEN_PORTS format (1)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE       1.1.1.1',
            'OPEN_PORTS   tcp',
            'KEY          testtest'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/Parse\serror/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'OPEN_PORTS format (2)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE       1.1.1.1',
            'OPEN_PORTS   icmp/22',
            'KEY          testtest'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/Invalid\sproto/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'OPEN_PORTS format (3)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE       1.1.1.1',
            'OPEN_PORTS   tcp/22, udp/53, tcp/12345, udp/123, icmp/1, tcp/23',
            'KEY          testtest'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/Invalid\sproto/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'access SOURCE key',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE     1.1.1.1',
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/No\skeys\sfound/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'access var too long',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE any',
            'KEY    ' . 'A'x1200
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/Invalid\saccess\sfile\sentry/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'iptables FORCE_NAT format (1)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE any',
            'FORCE_NAT a a'
        ],
        'server_conf_file' => [
            '### comment line'
        ],
        'positive_output_matches' => [qr/requires\s.*IPT_FORWARDING/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'iptables FORCE_NAT format (2)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE any',
            'FORCE_NAT a a'
        ],
        'server_conf_file' => [
            'ENABLE_IPT_FORWARDING      Y'
        ],
        'positive_output_matches' => [qr/need.*IP.*PORT/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'iptables FORCE_NAT format (3)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE any',
            'FORCE_NAT 1.2.3.4 999999'
        ],
        'server_conf_file' => [
            'ENABLE_IPT_FORWARDING      Y'
        ],
        'positive_output_matches' => [qr/invalid\sFORCE_NAT\sport/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'iptables FORCE_NAT format (4)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE any',
            'FORCE_NAT 1.2.3.4.9 1234'
        ],
        'server_conf_file' => [
            'ENABLE_IPT_FORWARDING      Y'
        ],
        'positive_output_matches' => [qr/invalid\sFORCE_NAT\sIP/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'iptables FORCE_SNAT format (1)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE any',
            'FORCE_SNAT 1.2.3.4.9 1234'
        ],
        'server_conf_file' => [
            'ENABLE_IPT_FORWARDING      Y'
        ],
        'positive_output_matches' => [qr/invalid\sFORCE_SNAT\sIP/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'iptables FORCE_SNAT format (2)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE any',
            'FORCE_SNAT a'
        ],
        'server_conf_file' => [
            'ENABLE_IPT_FORWARDING      Y'
        ],
        'positive_output_matches' => [qr/invalid\sFORCE_SNAT\sIP/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'iptables FORCE_SNAT format (3)',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE any',
            'FORCE_SNAT a'
        ],
        'server_conf_file' => [
            'ENABLE_IPT_FORWARDING      N'
        ],
        'positive_output_matches' => [qr/requires.*enabled/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'iptables FORCE_SNAT + NAT',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE         any',
            'KEY            testtest',
            'FORCE_SNAT     1.2.3.4'
        ],
        'server_conf_file' => [
            'ENABLE_IPT_FORWARDING      Y'
        ],
        'positive_output_matches' => [qr/must\salso\sbe\sused/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'server',
        'detail'   => 'iptables FORCE_MASQUERADE + NAT',
        'function' => \&server_conf_files,
        'fwknopd_cmdline' => $server_rewrite_conf_files,
        'exec_err' => $YES,
        'server_access_file' => [
            'SOURCE                 any',
            'KEY                    testtest',
            'FORCE_MASQUERADE       Y'
        ],
        'server_conf_file' => [
            'ENABLE_IPT_FORWARDING      Y'
        ],
        'positive_output_matches' => [qr/must\salso\sbe\sused/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode CBC',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode CBC",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*CBC/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode ECB',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode ECB",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*ECB/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode CFB',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode CFB",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*CFB/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode PCBC (unsupported)',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode PCBC",
        'positive_output_matches' => [qr/Invalid\sencryption\smode:\sPCBC/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode OFB',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode OFB",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*OFB/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode CTR',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode CTR",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*CTR/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode Asymmetric',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode \"Asymmetric\"",
        'positive_output_matches' => [qr/Must\sspecify\sGPG\srecipient/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'encryption mode legacy',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode legacy",
        'positive_output_matches' => [qr/Encryption\sMode\:\s.*legacy/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'bad encryption mode',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --test --encryption-mode badmode",
        'positive_output_matches' => [qr/Invalid\sencryption\smode:\sbadmode/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'pw bad file descriptor (1)',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args_no_get_key . " --test --fd -1",
        'positive_output_matches' => [qr/Value\s.*out\sof\srange/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'pw bad file descriptor (2)',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args_no_get_key . " --test --fd 100",
        'positive_output_matches' => [qr/Bad\sfile\sdescriptor/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'pw fd 0 PW_BS_CHAR',
        'function' => \&generic_exec,
        'cmdline'  => qq/perl -e 'print "test\x08test"' |/
                . $default_client_args_no_get_key . " --test --fd 0",
        'positive_output_matches' => [qr/FKO\sVersion/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'pw fd 0 PW_BREAK_CHAR',
        'function' => \&generic_exec,
        'cmdline'  => qq/perl -e 'print "test\x03test"' |/
                . $default_client_args_no_get_key . " --test --fd 0",
        'positive_output_matches' => [qr/FKO\sVersion/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'pw fd 0 PW_LF_CHAR',
        'function' => \&generic_exec,
        'cmdline'  => qq/perl -e 'print "test\x0atest"' |/
                . $default_client_args_no_get_key . " --test --fd 0",
        'positive_output_matches' => [qr/FKO\sVersion/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'pw fd 0 PW_CR_CHAR',
        'function' => \&generic_exec,
        'cmdline'  => qq/perl -e 'print "test\x0dtest"' |/
                . $default_client_args_no_get_key . " --test --fd 0",
        'positive_output_matches' => [qr/FKO\sVersion/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'pw fd 0 PW_CLEAR_CHAR',
        'function' => \&generic_exec,
        'cmdline'  => qq/perl -e 'print "test\x15test"' |/
                . $default_client_args_no_get_key . " --test --fd 0",
        'positive_output_matches' => [qr/FKO\sVersion/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'pw fd 0 HMAC key',
        'function' => \&generic_exec,
        'cmdline'  => qq/echo "hmackey" |/
                . "$default_client_args_no_get_key --use-hmac --key-rijndael enckey --test --fd 0",
        'positive_output_matches' => [qr/HMAC.*SHA256/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'pw fd 0 HMAC key long',
        'function' => \&generic_exec,
        'cmdline'  => qq/perl -e 'print "A"x1500' |/
                . "$default_client_args_no_get_key --use-hmac --key-rijndael enckey --test --fd 0",
        'positive_output_matches' => [qr/HMAC.*SHA256/],
    },
    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => 'pw fd 0 HMAC key NULL',
        'function' => \&generic_exec,
        'cmdline'  => qq/perl -e '' |/
                . "$default_client_args_no_get_key --use-hmac --key-rijndael enckey --test --fd 0",
        'positive_output_matches' => [qr/HMAC.*SHA256/],
    },

    {
        'category' => 'basic operations',
        'subcategory' => 'client',
        'detail'   => '--stanza-list',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_args . " --stanza-list --rc-file $cf{'rc_stanza_list'}",
        'positive_output_matches' => [qr/The\sfollowing\sstanzas\sare\sconfigured/i, qr/stanza_1/, qr/stanza_2/],
        'negative_output_matches' => [qr/default/],
    },
);
