@rijndael_hmac = (
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client',
        'detail'   => 'rc file HMAC base64 key (tcp/22 ssh)',
        'function' => \&generic_exec,
        'cmdline'  => $default_client_hmac_args,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client',
        'detail'   => 'validate HMAC type arg',
        'function' => \&generic_exec,
        'cmdline'  => "$default_client_hmac_args --hmac-digest-type invalid",
        'positive_output_matches' => [qr/Invalid\shmac\sdigest\stype/i],
        'exec_err' => $YES,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client',
        'detail'   => 'rc file invalid HMAC type arg',
        'function' => \&generic_exec,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_hmac_invalid_type'}",
        'positive_output_matches' => [qr/must\sbe\sone\sof/i],
        'exec_err' => $YES,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client',
        'detail'   => 'rc file HMAC+encryption keys not equal',
        'function' => \&generic_exec,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_hmac_equal_keys'}",
        'positive_output_matches' => [qr/should\snot\sbe\sidentical/i],
        'exec_err' => $YES,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'server',
        'detail'   => 'rc file HMAC+encryption keys not equal',
        'function' => \&generic_exec,
        'cmdline' =>  "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_equal_keys_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'positive_output_matches' => [qr/should\snot\sbe\sidentical/i],
        'exec_err' => $YES,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'server',
        'detail'   => 'access file invalid HMAC type arg',
        'function' => \&generic_exec,
        'cmdline' =>  "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_invalid_type_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'positive_output_matches' => [qr/must\sbe\sone\sof/i],
        'exec_err' => $YES,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'replay attack detection',
        'function' => \&replay_detection,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Replay\sdetected\sfrom\ssource\sIP/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (Rijndael prefix)',
        'function' => \&replay_detection,
        'cmdline'  => $default_client_hmac_args,
        'pkt_prefix' => 'U2FsdGVkX1',
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (GnuPG prefix)',
        'function' => \&replay_detection,
        'cmdline'  => $default_client_hmac_args,
        'pkt_prefix' => 'hQ',
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Args\scontain\sinvalid\sdata/],
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'iptables custom input chain',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'custom_input_chain'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/FWKNOP_INPUT_TEST\s\(1\sreferences/],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf'     => $cf{'custom_input_chain'},
        'key_file' => $cf{'rc_hmac_b64_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => '--get-hmac-key (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args .
            " --get-hmac-key $local_hmac_key_file",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_get_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'get_key' => {'file' => $local_key_file,
            'key' => 'rijndaelkey'},
        'get_hmac_key' => {'file' => $local_hmac_key_file,
            'key' => 'hmackey'},
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'iptables - no flush at init',
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'no_flush_init'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'iptables - no flush at exit',
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'no_flush_exit'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'iptables - no flush at init or exit',
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'no_flush_init_or_exit'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => '-f client timeout',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_hmac_args -f 2",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => '-f -1 client timeout err',
        'function' => \&generic_exec,
        'cmdline'  => qq|$default_client_hmac_args -f "-2"|,
        'positive_output_matches' => [qr/timeout\smust\sbe\swithin/],
        'exec_err' => $YES,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client->server compatibility',
        'detail'   => 'Cygwin Windows 2008',
        'function' => \&backwards_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '+NHb5ytzAppxOdX/sy48+nvGNzsR9Bq6wbaakwihbepSDlZWpBwG7HOv0V' .
            '1Lwzpt5/vYMkmzCr1aXdgBPJVkqMQQZppjkxMApQGbX0MXLPG+aqP9MGWr' .
            'mpOVjSY8vW5uc8wOhnNJFtu77jvR7MIDFOkNO16LbLV+IxQOmoJHE2+lUH' .
            '1nvudMWCORI/tzK/QU5YWFAXbbjFhR6RgvdWfzDhwxAEpNfd5gE',
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_cygwin_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/with expire time/],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {

        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'short IP 1.1.1.1 (ssh)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a 1.1.1.1 -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'no_ip_check' => 1
    },
    {

        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'long IP 123.123.123.123 (ssh)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a 123.123.123.123 -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'no_ip_check' => 1
    },

    {

        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/23)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/23 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'non-b64 HMAC key (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key2'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_no_b64_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key2'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/9418)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/9418 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/60001)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/60001 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'multi port (tcp/60001,udp/60001)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/60001,udp/60001 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'random SPA port (tcp/22)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_hmac_args -r",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            qq|-P "udp"|,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'random SPA port (via rc RAND_PORT)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_rand_port_hmac_b64_key'} $verbose_str -r",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            qq|-P "udp"|,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_rand_port_hmac_b64_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle simple keys',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_hmac_simple_key'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_simple_keys_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_simple_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'spoof username cycle (tcp/22)',
        'function' => \&spa_cycle,
        'cmdline'  => "SPOOF_USER=$spoof_user LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'rotate digest file',
        'function' => \&rotate_digest_file,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str --rotate-digest-cache",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client',
        'detail'   => "--save-packet $tmp_pkt_file",
        'function' => \&client_save_spa_pkt,
        'cmdline'  => "$default_client_hmac_args " .
            "--save-args-file $tmp_args_file " .
            "--save-packet $tmp_pkt_file",
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client',
        'detail'   => "--last-cmd",
        'function' => \&generic_exec,
        'cmdline' => "$fwknopCmd --last-cmd --save-args-file $tmp_args_file " .
            "$verbose_str",
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'permissions check cycle (tcp/22)',
        'function' => \&permissions_check,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'server_positive_output_matches' => [qr/permissions\sshould\sonly\sbe\suser/],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'client IP resolve (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $client_ip_resolve_hmac_args,
        'no_ip_check' => 1,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle MD5 (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_md5_key'} --hmac-digest-type md5",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_md5_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_md5_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle MD5 (short key)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_md5_short_key'} --hmac-digest-type md5",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_md5_short_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_md5_short_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle MD5 (long key)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_md5_long_key'} --hmac-digest-type md5",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_md5_long_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_md5_long_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA1 (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_hmac_args --hmac-digest-type sha1",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha1_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA1 (short key)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha1_short_key'} --hmac-digest-type sha1",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha1_short_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_sha1_short_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA1 (long key)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha1_long_key'} --hmac-digest-type sha1",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha1_long_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_sha1_long_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA256 (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_hmac_args --hmac-digest-type sha256",
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA256 (short key)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha256_short_key'} --hmac-digest-type sha256",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha256_short_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_sha256_short_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA256 (long key)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha256_long_key'} --hmac-digest-type sha256",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha256_long_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_sha256_long_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA384 (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha384_key'} --hmac-digest-type sha384",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha384_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_sha384_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA384 (short key)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha384_short_key'} --hmac-digest-type sha384",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha384_short_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_sha384_short_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA384 (long key)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha384_long_key'} --hmac-digest-type sha384",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha384_long_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_sha384_long_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA512 (long key)',
        'function' => \&generic_exec,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha512_long_key'} --hmac-digest-type sha512",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'key_file' => $cf{'rc_hmac_sha512_long_key'},
        'positive_output_matches' => [qr/Invalid\sdecoded\skey\slength/],
        'exec_err' => $YES,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA512 (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha512_key'} --hmac-digest-type sha512",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha512_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_sha512_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA512 (short key)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha512_short_key'} --hmac-digest-type sha512",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha512_short_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_sha512_short_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client',
        'detail'   => 'validate digest type arg',
        'function' => \&generic_exec,
        'cmdline'  => "$default_client_hmac_args --hmac-digest-type invaliddigest",
        'positive_output_matches' => [qr/Invalid\shmac\sdigest\stype/i],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'digest type mismatch (1)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha256_key'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha256_digest1_mismatch_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/stanza #1\).*\sArgs\scontain\sinvalid\sdata/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'key_file' => $cf{'rc_hmac_sha256_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'digest type mismatch (2)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha256_key'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha256_digest2_mismatch_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/stanza #1\).*\sArgs\scontain\sinvalid\sdata/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'key_file' => $cf{'rc_hmac_sha256_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'digest type mismatch (3)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha256_key'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha256_digest3_mismatch_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/stanza #1\).*\sArgs\scontain\sinvalid\sdata/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'key_file' => $cf{'rc_hmac_sha256_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'digest type mismatch (4)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_sha256_key'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha256_digest4_mismatch_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/stanza #1\).*\sArgs\scontain\sinvalid\sdata/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'key_file' => $cf{'rc_hmac_sha256_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'dual usage access key (tcp/80 http)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/80 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_dual_key_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        ### check for the first stanza that does not allow tcp/80 - the
        ### second stanza allows this
        'server_positive_output_matches' => [qr/stanza #1\)\sOne\sor\smore\srequested\sprotocol\/ports\swas\sdenied/],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'altered HMAC (tcp/22 ssh)',
        'function' => \&altered_hmac_spa_data,  ### alter HMAC itself
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_hmac_b64_key'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'altered pkt HMAC (tcp/22 ssh)',
        'function' => \&altered_pkt_hmac_spa_data,  ### alter SPA payload
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_hmac_b64_key'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "non-enabled NAT (tcp/22 ssh)",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} -N $internal_nat_host:22",
        'fwknopd_cmdline' =>  "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/requested\sNAT\saccess.*not\senabled/i],
        'server_conf' => $cf{'def'},
        'key_file' => $cf{'rc_hmac_b64_key'},
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "NAT to $internal_nat_host (tcp/22 ssh)",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} -N $internal_nat_host:22",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'nat'} -a $cf{'hmac_open_ports_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD\s.*dport\s22\s/,
            qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_conf' => $cf{'nat'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "SNAT $internal_nat_host",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} -N $internal_nat_host:22",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'snat'} -a $cf{'hmac_open_ports_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD\s.*dport\s22\s/,
            qr/to\:$internal_nat_host\:22/i],
        'no_ip_check' => 1,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_conf' => $cf{'snat'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "SNAT MASQUERADE",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} -N $internal_nat_host:22",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'snat_no_translate_ip'} -a $cf{'hmac_open_ports_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD\s.*dport\s22\s/,
            qr/to\:$internal_nat_host\:22/i,
            qr/MASQUERADE\s.*to\-ports/,
        ],
        'no_ip_check' => 1,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_conf' => $cf{'snat_no_translate_ip'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "iptables NAT custom chain",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} -N $internal_nat_host:22",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'custom_nat_chain'} -a $cf{'hmac_open_ports_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD_TEST\s.*dport\s22\s/,
            qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_conf' => $cf{'custom_nat_chain'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "NAT tcp/80 to $internal_nat_host tcp/22",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/80 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str -N $internal_nat_host:22",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'nat'} -a $cf{'hmac_open_ports_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD\s.*dport\s22\s/,
            qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'nat'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client',
        'detail'   => "NAT bogus IP validation",
        'function' => \&generic_exec,
        'exec_err' => $YES,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} -N 999.1.1.1:22",
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "force NAT $force_nat_host (tcp/22)",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            $cf{'rc_hmac_b64_key'},
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'nat'} -a $cf{'hmac_force_nat_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/\sto\:$force_nat_host\:22/i],
        'server_negative_output_matches' => [qr/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'nat'},
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "local NAT $force_nat_host (tcp/22)",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} --nat-local",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'local_nat'} -a $cf{'hmac_force_nat_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/to\:$force_nat_host\:22/i,
            qr/FWKNOP_INPUT.*dport\s22.*\sACCEPT/],
        'server_negative_output_matches' => [qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'local_nat'},
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "local NAT non-FORCE_NAT",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str --nat-local --nat-port 80",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'local_nat'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/to\:$loopback_ip\:22/i,
            qr/FWKNOP_INPUT.*dport\s22.*\sACCEPT/],
        'server_negative_output_matches' => [qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'local_nat'},
        'key_file' => $cf{'rc_hmac_b64_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "local NAT rand port to tcp/22",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str --nat-local --nat-rand-port",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'local_nat'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/to\:$loopback_ip\:22/i,
            qr/FWKNOP_INPUT.*dport\s22.*\sACCEPT/],
        'server_negative_output_matches' => [qr/to\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'local_nat'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "NAT rand port to tcp/22",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str --nat-rand-port -N $internal_nat_host",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'nat'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD.*dport\s22\s.*\sACCEPT/,
            qr/FWKNOP_PREROUTING.*\sDNAT\s.*to\-destination\s$internal_nat_host\:22/,
        ],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'nat'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "NAT rand port to -N <host>:40001",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str --nat-rand-port -N $internal_nat_host:40001",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'nat'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD.*dport\s40001\s.*\sACCEPT/,
            qr/FWKNOP_PREROUTING.*\sDNAT\s.*to\-destination\s$internal_nat_host\:40001/,
        ],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{'nat'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'iptables rules not duplicated',
        'function' => \&iptables_rules_not_duplicated,
        'cmdline'  => "$default_client_hmac_args --test",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'server',
        'detail'   => 'digest cache structure',
        'function' => \&digest_cache_structure,
    },

);
