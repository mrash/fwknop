
### need to add a lot more tests to this

@rijndael_hmac_cmd_exec = (
    ### command execution tests
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'command execution',
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --rc-file $cf{'rc_hmac_b64_key'} ".
            "$verbose_str",
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'command execution not allowed',
        'function' => \&spa_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --rc-file $cf{'rc_hmac_b64_key'} ".
            "$verbose_str",
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'server_positive_output_matches' => [qr/Command messages are not allowed/]
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'command execution (args too long)',
        'function' => \&spa_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "ls -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a" | .
            "-a $fake_ip -D $loopback_ip --rc-file $cf{'rc_hmac_b64_key'} ".
            "$verbose_str",
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'server_positive_output_matches' => [qr/max command line args exceeded/]
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'command execution (UDP server)',
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --rc-file $cf{'rc_hmac_b64_key'} ".
            "$verbose_str",
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str --udp-server",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'command exec UDP (args too long)',
        'function' => \&spa_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "ls -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a -a" | .
            "-a $fake_ip -D $loopback_ip --rc-file $cf{'rc_hmac_b64_key'} ".
            "$verbose_str",
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str --udp-server",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'server_positive_output_matches' => [qr/max command line args exceeded/]
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "command execution setuid 'nobody'",
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --rc-file $cf{'rc_hmac_b64_key'} ".
            "$verbose_str",
        'cmd_exec_file_owner' => 'nobody',
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_setuid_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => "command execution uid/gid 'nobody'",
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --rc-file $cf{'rc_hmac_b64_key'} ".
            "$verbose_str",
        'cmd_exec_file_owner' => 'nobody',
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_giduid_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

);
