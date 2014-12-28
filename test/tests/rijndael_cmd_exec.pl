
### need to add a lot more tests to this

@rijndael_cmd_exec = (
    ### command execution tests
    {
        'category' => 'Rijndael',
        'subcategory' => 'client+server',
        'detail'   => 'command execution',
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --get-key $local_key_file " .
            "$verbose_str",
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'cmd_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client+server',
        'detail'   => 'command execution (UDP server)',
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --get-key $local_key_file " .
            "$verbose_str",
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'cmd_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str --udp-server",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client+server',
        'detail'   => "command execution setuid 'nobody'",
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --get-key $local_key_file " .
            "$verbose_str",
        'cmd_exec_file_owner' => 'nobody',
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'cmd_setuid_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client+server',
        'detail'   => "command execution uid/gid 'nobody'",
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => qq|$fwknopCmd --server-cmd "touch $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --get-key $local_key_file " .
            "$verbose_str",
        'cmd_exec_file_owner' => 'nobody',
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'cmd_giduid_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

);
