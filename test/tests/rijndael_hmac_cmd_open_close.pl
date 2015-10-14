@rijndael_hmac_cmd_open_close = (
    ### command open/close cycle tests
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
);
