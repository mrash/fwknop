@rijndael_hmac_cmd_open_close = (
    ### command open/close cycle tests
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => '/tmp/127.0.0.2',
        'cmd_cycle_close_file' => '/tmp/2127.0.0.2',
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
);
