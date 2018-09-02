@ipv6 = (
    ### complete cycle tests
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'IPv6 client+server',
        'detail'   => 'complete cycle (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_hmac_args_ipv6,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "--ipv6 -d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_hmac_b64_key'},
    },
)
