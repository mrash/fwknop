
### need to add a lot more tests to this

@rijndael_cmd_exec = (
    ### command execution tests
    {
        'category' => 'Rijndael',
        'subcategory' => 'client+server',
        'detail'   => 'command execution',
        'function' => \&spa_cmd_exec_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            qq|$fwknopCmd --server-cmd "echo fwknoptest > $cmd_exec_test_file" | .
            "-a $fake_ip -D $loopback_ip --get-key $local_key_file " .
            "--verbose --verbose",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'def'} -a $cf{'cmd_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },
);
