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
        'detail'   => '3 cycles (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'client_cycles_per_server_instance' => 3,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cycle DESTINATION accepted (1)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'spa_destnation'} " .
            "-a $cf{'hmac_spa_destination_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/\b$fake_ip\s.*$loopback_ip\b/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cycle DESTINATION accepted (2)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'spa_destnation'} " .
            "-a $cf{'hmac_spa_destination2_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cycle DESTINATION accepted (3)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'spa_destnation'} " .
            "-a $cf{'hmac_spa_destination3_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cycle DESTINATION filtered (1)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'spa_destnation'} " .
            "-a $cf{'hmac_spa_destination4_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'client_pkt_tries' => 2,
        'server_receive_re' => qr/SPA\spacket\s.*filtered\sby\sSOURCE.*DEST/,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cycle DESTINATION filtered (2)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'spa_destnation'} " .
            "-a $cf{'hmac_spa_destination5_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'client_pkt_tries' => 2,
        'server_receive_re' => qr/SPA\spacket\s.*filtered\sby\sSOURCE.*DEST/,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => '--ipt-no-check-support',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "$intf_str --no-ipt-check-support --no-firewd-check-support",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => '3 cycles --ipt-no-check-support',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "$intf_str --no-ipt-check-support --no-firewd-check-support",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'client_cycles_per_server_instance' => 3,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => '--ipt-no-check dupe rule',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "$intf_str --no-ipt-check-support --no-firewd-check-support",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $REQUIRE_NO_NEW_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'insert_duplicate_rule_while_running' => $YES,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'rm rule mid-cycle',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'rm_rule_mid_cycle' => $YES,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'dupe rule mid-cycle',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $REQUIRE_NO_NEW_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'insert_duplicate_rule_while_running' => $YES,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => '--ipt-no-check-support udp/53',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A udp/53 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str " .
            "--no-ipt-check-support --no-firewd-check-support",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "$FW_TYPE OUTPUT chain",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_output_chain"} -a $cf{'hmac_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle rc defaults',
        'function' => \&spa_cycle,
        'cmdline'  => $client_hmac_rc_defaults,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_defaults'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle time offset mins',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_hmac_time_offset_mins'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_time_offset_mins'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle time offset hours',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_hmac_time_offset_hours'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_time_offset_hours'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle time offset days',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key " .
            "--rc-file $cf{'rc_hmac_time_offset_days'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_time_offset_days'},
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
        'subcategory' => 'server',
        'detail'   => '--pcap-file processing',
        'function' => \&process_pcap_file_directly,
        'cmdline'  => '',
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "--pcap-file $multi_pkts_pcap_file --foreground $verbose_str " .
            "--verbose --verbose --verbose",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'server',
        'detail'   => '--pcap-file SPA over http',
        'function' => \&process_pcap_file_directly,
        'cmdline'  => '',
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'spa_over_http'} -a $cf{'hmac_sha256_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "--pcap-file $spa_over_http_pcap_file --foreground $verbose_str " .
            "--pcap-filter 'port 80' " .
            "--verbose --verbose --verbose",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'server',
        'detail'   => '--pcap-file with Ethernet FCS header',
        'function' => \&process_pcap_file_directly,
        'cmdline'  => '',
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file " .
            "--pcap-file $fcs_pcap_file --foreground $verbose_str " .
            "--verbose --verbose --verbose",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "$FW_TYPE custom input chain",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_custom_input_chain"} -a $cf{'hmac_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/FWKNOP_INPUT_TEST\s\(1\sreferences/],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf'     => $cf{"${fw_conf_prefix}_custom_input_chain"},
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
        'detail'   => "$FW_TYPE - no flush at init",
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_no_flush_init"} -a $cf{'hmac_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "$FW_TYPE - no flush at exit",
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_no_flush_exit"} -a $cf{'hmac_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "$FW_TYPE - no flush at init or exit",
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_no_flush_init_or_exit"} -a $cf{'hmac_access'} / .
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
        'subcategory' => 'Android compatibility',
        'detail'   => 'v4.4',
        'function' => \&backwards_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '+8fP34T9Vjs50Yke5tNTz7YnsDbQUcp6zaaJTzVOgRuNXyhiZKL5' .
            'UpaC2neRkqgjSlG6/qJSKXIuXBKR4LFS3rX2ZwrOkfBGKJeXe8S2' .
            'uZex9RjOr/8SwS45Q+Kt3J6QsShXU4cxz09Cv+bi7+08/bGCyVdh' .
            'vYNwogIhEkcqS79+JNR3lSBEBrOY4hoOKRRAYw41yI5cBCdc',
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_android_access'} " .
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
        'detail'   => 'random SPA port (portrange filter)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_hmac_args -r",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'portrange_filter'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
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
        'detail'   => 'spoof user via --spoof-user',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 --spoof-user $spoof_user -a $fake_ip -D $loopback_ip --rc-file " .
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
        'detail'   => 'spoof src IP 3.3.3.3 (tcp/22)',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -P udpraw -Q 3.3.3.3 -D $loopback_ip --rc-file " .
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
        'detail'   => 'rc file spoof src IP (tcp/22)',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_spoof_src_b64_key'} $verbose_str",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_spoof_src_b64_key'},
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
        'function' => \&run_last_args,
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
        'detail'   => 'SPA through HTTP proxy',
        'function' => \&generic_exec,
        'cmdline'  => "$default_client_hmac_args -H $resolve_url_with_port --test",
        'no_ip_check' => 1,
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
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
        'detail'   => 'client IP --resolve-url <def>',
        'function' => \&spa_cycle,
        'cmdline'  => "$client_ip_resolve_hmac_args " .
            "--resolve-url https://www.cipherdyne.org/cgi-bin/myip",
        'no_ip_check' => 1,
        'positive_output_matches' => [qr/wget/],
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'client IP --resolve-http-only',
        'function' => \&spa_cycle,
        'cmdline'  => "$client_ip_resolve_hmac_args --resolve-http-only",
        'no_ip_check' => 1,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'client IP resolve manual URL',
        'function' => \&spa_cycle,
        'cmdline'  => "$client_ip_resolve_hmac_args --resolve-url $resolve_url",
        'no_ip_check' => 1,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'client IP resolve URL with port',
        'function' => \&spa_cycle,
        'cmdline'  => "$client_ip_resolve_hmac_args --resolve-url $resolve_url_with_port",
        'no_ip_check' => 1,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'client IP resolve URL + user-agent',
        'function' => \&spa_cycle,
        'cmdline'  => "$client_ip_resolve_hmac_args --resolve-url $resolve_url_with_port -u FwknopTestSuite/2.6",
        'no_ip_check' => 1,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'client IP wget user-agent',
        'function' => \&spa_cycle,
        'cmdline'  => "$client_ip_resolve_hmac_args --use-wget-user-agent",
        'no_ip_check' => 1,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'client IP resolve rc file',
        'function' => \&spa_cycle,
        'cmdline'  => $client_hmac_rc_http_resolve,
        'no_ip_check' => 1,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_http_resolve'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'client IP resolve rc file (2)',
        'function' => \&spa_cycle,
        'cmdline'  => $client_hmac_rc_https_resolve,
        'no_ip_check' => 1,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_https_resolve'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'client IP resolve rc file (3)',
        'function' => \&spa_cycle,
        'cmdline'  => $client_hmac_rc_http_only_resolve,
        'no_ip_check' => 1,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_hmac_conf_args $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_http_only_resolve'},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client',
        'detail'   => 'client IP --resolve-http-only vs HTTPS',
        'function' => \&generic_exec,
        'cmdline'  => "$client_ip_resolve_hmac_args --resolve-http-only " .
            "--resolve-url https://somedomain.com/myip",
        'no_ip_check' => 1,
        'positive_output_matches' => [qr/not.*supported/i],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client',
        'detail'   => 'client IP resolve invalid port',
        'function' => \&generic_exec,
        'cmdline'  => "$client_ip_resolve_hmac_args --resolve-url http://somedomain.com:99999/myip",
        'no_ip_check' => 1,
        'positive_output_matches' => [qr/port.*invalid/i],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
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
        'subcategory' => 'client+server',
        'detail'   => "UDP server --udp-server / tcp/22",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str --udp-server -vvv",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "3 cycles UDP server / tcp/22",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str --udp-server -vvv",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'client_cycles_per_server_instance' => 3,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "UDP server conf / tcp/22",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'udp_server'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
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
        'weak_server_receive_check' => $YES,
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
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_nat"} -a $cf{'hmac_open_ports_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD\s.*dport\s22\s/,
            qr/\*\/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_conf' => $cf{"${fw_conf_prefix}_nat"},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "SNAT $internal_nat_host",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} -N $internal_nat_host:22",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_snat"} -a $cf{'hmac_open_ports_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD\s.*dport\s22\s/,
            qr/\*\/\sto\:$internal_nat_host\:22/i],
        'no_ip_check' => 1,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_conf' => $cf{"${fw_conf_prefix}_snat"},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "SNAT MASQUERADE",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} -N $internal_nat_host:22",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_snat_no_translate_ip"} -a $cf{'hmac_open_ports_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD\s.*dport\s22\s/,
            qr/\*\/\sto\:$internal_nat_host\:22/i,
            qr/MASQUERADE\s.*to\-ports/,
        ],
        'no_ip_check' => 1,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_conf' => $cf{"${fw_conf_prefix}_snat_no_translate_ip"},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "$FW_TYPE NAT custom chain",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} -N $internal_nat_host:22",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_custom_nat_chain"} -a $cf{'hmac_open_ports_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD_TEST\s.*dport\s22\s/,
            qr/\*\/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_conf' => $cf{"${fw_conf_prefix}_custom_nat_chain"},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "NAT tcp/80 to $internal_nat_host tcp/22",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/80 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str -N $internal_nat_host:22",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_nat"} -a $cf{'hmac_open_ports_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD\s.*dport\s22\s/,
            qr/\*\/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_nat"},
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
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_nat"} -a $cf{'hmac_force_nat_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/\*\/\sto\:$force_nat_host\:22/i],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_nat"},
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "force SNAT $force_snat_host (tcp/22)",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            $cf{'rc_hmac_b64_key'},
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_snat"} -a $cf{'hmac_force_snat_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/DNAT\s.*\*\/\sto\:$force_nat_host2\:22/i,
            qr/SNAT\s.*\*\/\sto\:$force_snat_host\:22/],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i,
            qr/\*\/\sto\:$force_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_snat"},
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "force SNAT $force_snat_host (ipt flush)",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            $cf{'rc_hmac_b64_key'},
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_snat"} -a $cf{'hmac_force_snat_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/DNAT\s.*\*\/\sto\:$force_nat_host2\:22/i,
            qr/SNAT\s.*\*\/\sto\:$force_snat_host\:22/],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i,
            qr/\*\/\sto\:$force_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_snat"},
        'key_file' => $cf{'rc_hmac_b64_key'},
        'iptables_rm_chains_after_server_start' => $YES,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "force MASQ $force_snat_host (tcp/22)",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            $cf{'rc_hmac_b64_key'},
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_snat_no_translate_ip"} -a $cf{'hmac_force_masq_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/DNAT\s.*\*\/\sto\:$force_nat_host2\:22/i,
            qr/MASQUERADE\s.*\s$force_nat_host2\s.*\smasq\sports\:\s22/],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i,
            qr/\*\/\sto\:$force_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_snat_no_translate_ip"},
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "force MASQ $force_snat_host (ipt flush)",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            $cf{'rc_hmac_b64_key'},
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_snat_no_translate_ip"} -a $cf{'hmac_force_masq_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/DNAT\s.*\*\/\sto\:$force_nat_host2\:22/i,
            qr/MASQUERADE\s.*\s$force_nat_host2\s.*\smasq\sports\:\s22/],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i,
            qr/\*\/\sto\:$force_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_snat_no_translate_ip"},
        'key_file' => $cf{'rc_hmac_b64_key'},
        'iptables_rm_chains_after_server_start' => $YES,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "force NAT ($FW_TYPE flush)",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            $cf{'rc_hmac_b64_key'},
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_nat"} -a $cf{'hmac_force_nat_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/\*\/\sto\:$force_nat_host\:22/i],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_nat"},
        'key_file' => $cf{'rc_hmac_b64_key'},
        'iptables_rm_chains_after_server_start' => $YES,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "local NAT $force_nat_host (tcp/22)",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} --nat-local",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_local_nat"} -a $cf{'hmac_force_nat_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/\*\/\sto\:$force_nat_host\:22/i,
            qr/FWKNOP_INPUT.*dport\s22.*\sACCEPT/],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_local_nat"},
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "local NAT ($FW_TYPE flush)",
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_args_no_get_key --rc-file " .
            "$cf{'rc_hmac_b64_key'} --nat-local",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_local_nat"} -a $cf{'hmac_force_nat_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr/\*\/\sto\:$force_nat_host\:22/i,
            qr/FWKNOP_INPUT.*dport\s22.*\sACCEPT/],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_local_nat"},
        'key_file' => $cf{'rc_hmac_b64_key'},
        'iptables_rm_chains_after_server_start' => $YES,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "local (non-force) NAT",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str --nat-local --nat-port 80",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_local_nat"} -a $cf{'hmac_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr|\s\*\/\sto\:$loopback_ip\:22|i,
            qr/ACCEPT\s{2}.*\s0\.0\.0\.0\/0\s+tcp\sdpt\:22\s/],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_local_nat"},
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "local (non-force) NAT ($FW_TYPE flush)",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str --nat-local --nat-port 80",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_local_nat"} -a $cf{'hmac_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr|\s\*\/\sto\:$loopback_ip\:22|i,
            qr/ACCEPT\s{2}.*\s0\.0\.0\.0\/0\s+tcp\sdpt\:22\s/],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_local_nat"},
        'key_file' => $cf{'rc_hmac_b64_key'},
        'iptables_rm_chains_after_server_start' => $YES,
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "local NAT rand port to tcp/22",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str --nat-local --nat-rand-port",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_local_nat"} -a $cf{'hmac_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [qr|\s\*\/\sto\:$loopback_ip\:22|i,
            qr/ACCEPT\s{2}.*\s0\.0\.0\.0\/0\s+tcp\sdpt\:22\s/],
        'server_negative_output_matches' => [qr/\*\/\sto\:$internal_nat_host\:22/i],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_local_nat"},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "NAT rand port to tcp/22",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str --nat-rand-port -N $internal_nat_host",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_nat"} -a $cf{'hmac_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD.*dport\s22\s.*\sACCEPT/,
            qr/FWKNOP_PREROUTING.*\sDNAT\s.*to\-destination\s$internal_nat_host\:22/,
        ],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_nat"},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "rc NAT rand port to tcp/22",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_nat_rand_b64_key'} $verbose_str -N $internal_nat_host",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_nat"} -a $cf{'hmac_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD.*dport\s22\s.*\sACCEPT/,
            qr/FWKNOP_PREROUTING.*\sDNAT\s.*to\-destination\s$internal_nat_host\:22/,
        ],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_nat"},
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "NAT rand port to -N <host>:40001",
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_hmac_b64_key'} $verbose_str --nat-rand-port -N $internal_nat_host:40001",
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_nat"} -a $cf{'hmac_access'} / .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'server_positive_output_matches' => [
            qr/FWKNOP_FORWARD.*dport\s40001\s.*\sACCEPT/,
            qr/FWKNOP_PREROUTING.*\sDNAT\s.*to\-destination\s$internal_nat_host\:40001/,
        ],
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_conf' => $cf{"${fw_conf_prefix}_nat"},
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "$FW_TYPE rules not duplicated",
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
