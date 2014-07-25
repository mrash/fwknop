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
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle no sig verify',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'gpg_no_sig_verify_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'invalid sig list',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'gpg_invalid_sig_id_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'fingerprint complete cycle tcp/22',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'gpg_no_pw_fpr_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'altered SPA packet',
        'function' => \&fuzzer,
        'no_ip_check' => 1,
        'fuzzing_pkt' =>
            'IOA3yoH1L5ONECEAf+L9UYYzzaj1uhy8IdHYVEnJaQuUuttUbtzXKjBfWShyXwgSIoq5' .
            '3TUIGvrQME356SRtG4Pfy1wv6Z2hi/Gn2zDnycJBSWtYZ+QGfkJQrv+RDmUafuRnW7Me' .
            'nnHekStRjFh05/2ojEz3/YrWG87JtpkPq1MTQFQkLg4TDc9liS39VUHQ8GW/c4iMQHKb' .
            'tZaW/d8w8YU6x98d0LltibnEL0zsjPs2KR9gEJRPr0TYMiPzSnBzlIKanTDaJwY33ycH' .
            'iBvFnqKLThIkDE3gz0mVTOMVuXgAkFQl9O8Lpw19B5kILBN3IxQdaVOBGi824fEQk7Ov' .
#            '/V3g1tIGDP3D/HkMDFOAf9FYWZJG4L5KsQGL2wpUpdnpZN2kjZt08q2cgqfDTzi0Lfst' .
            'AV3g1tIGDP3D/HkMDFOAf9FYWZJG4L5KsQGL2wpUpdnpZN2kjZt08q2cgqfDTzi0Lfst' .  ### the first byte was altered to 'A'
            '2i1raz3EPljOYhMcQBHjuMi+pC9D2KDCzCJBCaUIVskZ5PjBRgU+RrOaWtzLe65Bz1AM' .
            'exeDhr7Ap5S8Z1Zb9JDY5nA+ZrG5KPPG5VEn8K9LDSSPDp03XU5fdtG2UBEDVIz/zm42' .
            '9ii8cZkgFsKf8agX+dPdkiQqF1GRi6uj2FE1WtbXiGGUWcw+2uiXxHcV9k2fp9dSa7BZ' .
            'lNEN+hYxNETkkS8ohFEF0U4F2Dpi4tx0ajXjNKW+N1rK84zBxasH9hbiiMD+Yrc54HWZ' .
            '+LW53nUqMT3UH7+Dg6KTSUUNLAPgEyuliGtw1AX62qBcwCK8hRasMaYfB856xdPFDFQD' .
            'A7ZSBSDjXs1dBYR8n47lftru97zZDSZRfLLtJteeHB8eoiu9RwaqRd7x548nGxmIrlBw' .
            'zvovRVytMYMml1OcjCPdR9PsAUJm92m+6TeBSMMG3Hp4pkE85nqbrrjqTYzrnDekZYYX' .
            '6W8z6pU3JBDOu+B7HeI9HzxaKB77Q7fyOUCNZy0d/nH8ehcUebu7yz434zrOI/+WYeJB' .
            '7F+A59xJREA8pfYtd9SXzlou39AAMtqi90pvWlAMrTgBGWiRFsDbR0V4F+dgqcFvX7Ir' .
            'tcznNnYMt8cOrZsRlkURdSIhx8',
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} " .
            "-a $cf{'gpg_no_pw_fpr_access'} $intf_str --gpg-home-dir conf/server-gpg-no-pw " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'invalid fingerprint',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'gpg_no_pw_bad_fpr_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'server_positive_output_matches' => [qr/not in the GPG_FINGERPRINT/],
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'multi gpg-IDs (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'multi_gpg_no_pw_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'iptables - no flush at init',
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'no_flush_init'} " .
            "-a $cf{'multi_gpg_no_pw_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'iptables - no flush at exit',
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'no_flush_exit'} " .
            "-a $cf{'multi_gpg_no_pw_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'iptables - no flush at init or exit',
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_gpg_args_no_pw,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'no_flush_init_or_exit'} " .
            "-a $cf{'multi_gpg_no_pw_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/23 telnet)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/23 -a $fake_ip -D $loopback_ip " .
            "--gpg-no-signing-pw $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/9418 git)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/9418 -a $fake_ip -D $loopback_ip " .
            "--gpg-no-signing-pw $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/60001)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/60001 -a $fake_ip -D $loopback_ip " .
            "--gpg-no-signing-pw $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (udp/53 dns)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A udp/53 -a $fake_ip -D $loopback_ip " .
            "--gpg-no-signing-pw $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir_no_pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
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
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (Rijndael prefix)',
        'function' => \&replay_detection,
        'pkt_prefix' => 'U2FsdGVkX1',
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (GnuPG prefix)',
        'function' => \&replay_detection,
        'pkt_prefix' => 'hQ',
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
    },

    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'non-base64 altered SPA data',
        'function' => \&altered_non_base64_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'base64 altered SPA data',
        'function' => \&altered_base64_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'appended data to SPA pkt',
        'function' => \&appended_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
    },
    {
        'category' => 'GPG (no pw)',
        'subcategory' => 'client+server',
        'detail'   => 'prepended data to SPA pkt',
        'function' => \&prepended_spa_data,
        'cmdline'  => "$default_client_gpg_args_no_homedir "
            . "--gpg-home-dir $gpg_client_home_dir_no_pw --gpg-no-signing-pw",
        'fwknopd_cmdline'  => $default_server_gpg_args_no_pw,
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
    },
);
