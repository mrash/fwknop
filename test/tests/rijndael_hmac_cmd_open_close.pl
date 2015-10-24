@rijndael_hmac_cmd_open_close = (
    ### command open/close cycle tests
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (1)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => '/tmp/127.0.0.2',
        'cmd_cycle_close_file' => '/tmp/2127.0.0.2',
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (2)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access2'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => '/tmp/127.0.0.2_22_6TEST',
        'cmd_cycle_close_file' => '/tmp/2127.0.0.2_22_6TEST',
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (3)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access3'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => '/tmp/127.0.0.2_127.0.0.2',
        'cmd_cycle_close_file' => '/tmp/2127.0.0.2_127.0.0.2',
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (4)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access4'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => '/tmp/127.0.0.2_127.0.0.1',
        'cmd_cycle_close_file' => '/tmp/2127.0.0.1_127.0.0.2',
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (5)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access5'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => '/tmp/127.0.0.2127.0.0.1',
        'cmd_cycle_close_file' => '/tmp/2127.0.0.1127.0.0.2',
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (UDP server)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access'} --udp-server " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => '/tmp/127.0.0.2',
        'cmd_cycle_close_file' => '/tmp/2127.0.0.2',
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (3 cycles)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args .
            " && $default_client_hmac_args" .
            " && $default_client_hmac_args",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => '/tmp/127.0.0.2',
        'cmd_cycle_close_file' => '/tmp/2127.0.0.2',
        'relax_receive_cycle_num_check' => $YES, ### multiple SPA packets involved
        'weak_server_receive_check' => $YES,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'sleep_cycles' => 6,
        'server_positive_output_matches' => [qr/Timer expired/],
    },

);
