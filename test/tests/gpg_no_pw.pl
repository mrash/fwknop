@gpg_no_pw = (
    ### no password GPG testing
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline' => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'multi gpg-IDs (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir " .
            "$valgrind_str $fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'multi_gpg_no_pw_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'iptables - no flush at init',
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir " .
            "$valgrind_str $fwknopdCmd -c $cf{'no_flush_init'} " .
            "-a $cf{'multi_gpg_no_pw_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'iptables - no flush at exit',
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir " .
            "$valgrind_str $fwknopdCmd -c $cf{'no_flush_exit'} " .
            "-a $cf{'multi_gpg_no_pw_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'iptables - no flush at init or exit',
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir " .
            "$valgrind_str $fwknopdCmd -c $cf{'no_flush_init_or_exit'} " .
            "-a $cf{'multi_gpg_no_pw_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/23 telnet)',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/23 -a $fake_ip -D $loopback_ip " .
            "--gpg-no-signing-pw --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/9418 git)',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/9418 -a $fake_ip -D $loopback_ip " .
            "--gpg-no-signing-pw --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/60001)',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A tcp/60001 -a $fake_ip -D $loopback_ip " .
            "--gpg-no-signing-pw --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (udp/53 dns)',
        'function' => \&spa_cycle,
        'cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopCmd -A udp/53 -a $fake_ip -D $loopback_ip " .
            "--gpg-no-signing-pw --verbose --verbose " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'replay attack detection',
        'function' => \&replay_detection,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'server_positive_output_matches' => [qr/Replay\sdetected\sfrom\ssource\sIP/],
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (Rijndael prefix)',
        'function' => \&replay_detection,
        'pkt_prefix' => 'U2FsdGVkX1',
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (GnuPG prefix)',
        'function' => \&replay_detection,
        'pkt_prefix' => 'hQ',
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
        'fatal'    => $NO
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'non-base64 altered SPA data',
        'function' => \&altered_non_base64_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'base64 altered SPA data',
        'function' => \&altered_base64_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'appended data to SPA pkt',
        'function' => \&appended_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'prepended data to SPA pkt',
        'function' => \&prepended_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fatal'    => $NO
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'spoof username (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => "SPOOF_USER=$spoof_user $default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'positive_output_matches' => [qr/Username:\s*$spoof_user/],
        'server_positive_output_matches' => [qr/Username:\s*$spoof_user/],
        'fatal'    => $NO
    },
);
