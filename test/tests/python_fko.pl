@python_fko = (
    {
        'category' => 'python fko extension',
        'subcategory' => 'compile/install',
        'detail'   => 'to: ./python_fko/',
        'function' => \&python_fko_compile_install,
    },
    {
        'category' => 'python fko extension',
        'subcategory' => 'basic exec',
        'detail'   => 'import and use fko',
        'function' => \&python_fko_basic_exec,
    },
    {
        'category' => 'python fko extension',
        'subcategory' => 'compatibility',
        'detail'   => 'python -> C server',
        'function' => \&python_fko_client_to_C_server,
        'fwknopd_cmdline'  => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_sha512_short_key2_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

);
