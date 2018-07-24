
@configure_args = (

    ### UDP server mode only - make sure fwknopd does not link
    ### against libpcap
    {
        'category' => 'configure args',
        'subcategory' => 'compile',
        'detail'   => '--enable-udp-server no libpcap linkage',
        'function' => \&configure_args_udp_server_no_libpcap,
    },
    {
        'category' => 'configure args',
        'subcategory' => 'Rijndael+HMAC',
        'detail'   => "UDP server --udp-server / tcp/22",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str --udp-server",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'configure args',
        'subcategory' => 'Rijndael+HMAC',
        'detail'   => "3 cycles UDP server / tcp/22",
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str --udp-server",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'client_cycles_per_server_instance' => 3,
    },

    {
        'category' => 'configure args',
        'subcategory' => 'Rijndael+HMAC',
        'detail'   => 'command execution (UDP server)',
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --rc-file $cf{'rc_hmac_b64_key'} ".
            "$verbose_str",
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str --udp-server",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    ### disable execvp() usage
    {
        'category' => 'configure args',
        'subcategory' => 'compile',
        'detail'   => '--disable-execvp check',
        'function' => \&configure_args_disable_execvp,
    },
    {
        'category' => 'configure args',
        'subcategory' => 'Rijndael+HMAC',
        'detail'   => 'complete cycle (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/without execvp/],
    },
    {
        'category' => 'configure args',
        'subcategory' => 'Rijndael+HMAC',
        'detail'   => '3 cycles (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/without execvp/],
        'client_cycles_per_server_instance' => 3,
    },

    {
        'category' => 'configure args',
        'subcategory' => 'Rijndael+HMAC',
        'detail'   => 'command execution',
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --rc-file $cf{'rc_hmac_b64_key'} ".
            "$verbose_str",
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'server_positive_output_matches' => [qr/without execvp/],
    },

    ### restore original ./configure args to be prepared to run
    ### through the remainder of the tests
    {
        'category' => 'configure args',
        'subcategory' => 'compile',
        'detail'   => 'restore previous config args',
        'function' => \&configure_args_restore_orig,
    }
);
