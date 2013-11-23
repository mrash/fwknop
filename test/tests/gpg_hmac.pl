@gpg_hmac = (

    ### GPG testing (with passwords associated with keys) - first check to
    ### see if pinentry is required and disable remaining GPG tests if so
    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'pinentry not required',
        'function' => \&gpg_pinentry_check,
        'cmdline'  => $default_client_gpg_args,
    },

    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args
            . " --rc-file $cf{'rc_gpg_hmac_b64_key'}",
        'fwknopd_cmdline' => $default_server_gpg_args_hmac,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_gpg_hmac_b64_key'},
    },
    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle SHA512',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args
            . " --rc-file $cf{'rc_gpg_hmac_sha512_b64_key'}",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'gpg_hmac_sha512_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_gpg_hmac_sha512_b64_key'},
    },
    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'gpg args from rc file',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_args
            . " --rc-file $cf{'rc_gpg_args_hmac_b64_key'}",
        'fwknopd_cmdline' => $default_server_gpg_args_hmac,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_gpg_args_hmac_b64_key'},
    },

    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/23 telnet)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/23 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir " .
            "--rc-file $cf{'rc_gpg_hmac_b64_key'}",
        'fwknopd_cmdline'  => $default_server_gpg_args_hmac,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_gpg_hmac_b64_key'},
    },
    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/9418 git)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/9418 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir " .
            "--rc-file $cf{'rc_gpg_hmac_b64_key'}",
        'fwknopd_cmdline'  => $default_server_gpg_args_hmac,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_gpg_hmac_b64_key'},
    },
    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/60001 git)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/60001 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir " .
            "--rc-file $cf{'rc_gpg_hmac_b64_key'}",
        'fwknopd_cmdline'  => $default_server_gpg_args_hmac,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_gpg_hmac_b64_key'},
    },
    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (udp/53 dns)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A udp/53 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir " .
            "--rc-file $cf{'rc_gpg_hmac_b64_key'}",
        'fwknopd_cmdline'  => $default_server_gpg_args_hmac,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_gpg_hmac_b64_key'},
    },
    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'replay attack detection',
        'function' => \&replay_detection,
        'cmdline'  => "$default_client_gpg_args "
            . "--rc-file $cf{'rc_gpg_hmac_b64_key'}",
        'fwknopd_cmdline'  => $default_server_gpg_args_hmac,
        'key_file' => $cf{'rc_gpg_hmac_b64_key'},
    },
    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (Rijndael prefix)',
        'function' => \&replay_detection,
        'pkt_prefix' => 'U2FsdGVkX1',
        'cmdline'  => "$default_client_gpg_args " .
            "--gpg-home-dir $gpg_client_home_dir " .
            "--rc-file $cf{'rc_gpg_hmac_b64_key'}",
        'fwknopd_cmdline'  => $default_server_gpg_args_hmac,
        'server_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
    },
    {
        'category' => 'GPG+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (GnuPG prefix)',
        'function' => \&replay_detection,
        'pkt_prefix' => 'hQ',
        'cmdline'  => "$default_client_gpg_args " .
            "--gpg-home-dir $gpg_client_home_dir " .
            "--rc-file $cf{'rc_gpg_hmac_b64_key'}",
        'fwknopd_cmdline'  => $default_server_gpg_args_hmac,
        'server_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
    },

);
