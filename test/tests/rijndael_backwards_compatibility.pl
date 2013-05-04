@rijndael_backwards_compatibility = (
    ### backwards compatibility tests
    {
        'category' => 'Rijndael',
        'subcategory' => 'client->server backwards compatibility',
        'detail'   => 'v2.0',
        'function' => \&backwards_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '9ptGrLs8kVGVludcXFy17opvThEYzTeaT7RVlCN66W/G9QZs9BBevEQ0xxI8eCn' .
            'KPDM+Bu9g0XwmCEVxxg+4jwBwtbCxVt9t5aSR29EVWZ6UAOwLkunK3t4FYBy1tL' .
            '55krFt+1B2TtNSAH005kyDEZEOIGoY9Q/iU',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client->server backwards compatibility',
        'detail'   => 'v2.0.1',
        'function' => \&backwards_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '+uAD6hlS2BHuaCtVKIGyIsB/4U8USqcP9o4aT6FvBuPKORwTV8byyzv6bzZYINs4' .
            'Voq3QvBbIwkXJ63/oU+XxvP5R+DBLEnh3e/NHPFK6NB0WT2dujVyVxwBfvvWjIqW' .
            'Hhro2tH34nqfTRIpevfLTMx7r+N8ZQ4V8',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client->server backwards compatibility',
        'detail'   => 'v2.0.2',
        'function' => \&backwards_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '+mS70t2A2YmV50KgwDyy6nYLwzQ7AUO8pA/eatm7g9xc83xy1z7VOXeAYrgAOWy' .
            'Ksk30QvkwHtPhl7I0oDz1bO+2K2JbDbyc0KBBzVNMLgJcuYgEpOXPkX2XhcTsgQ' .
            'Vw2/Va/aUjvEvNPtwuipQS6DLTzOw/qy+/g',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client->server backwards compatibility',
        'detail'   => 'v2.0.3',
        'function' => \&backwards_compatibility,
        'pkt' =>
            '+8OtxmTJPgQmrXZ7hAqTopLBC/thqHNuPHTfR234pFuQOCZUikPe0inHmjfnQFnP' .
            'Sop/Iy6v+BCn9D+QD7eT7JI6BIoKp14K+8iNgKaNw1BdfgF1XDulpkNEdyG0fXz5' .
            'M+GledHfz2d49aYThoQ2Cr8Iw1ycViawY',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'client->server backwards compatibility',
        'detail'   => 'v2.0.4',
        'function' => \&backwards_compatibility,
        'pkt' =>
            '8Xm8U5vQ03T88UTCWbwO3t/aL6euZ8IgVbNdDVz3Bn6HkTcBqxcME95U/G3bCH' .
            'vQznpnGb05Md4ZgexHZGzZdSwsP8iVtcZdsgCBfeO4Eqs8OaSMjJVF8SQ+Jmhu' .
            'XZMcWgMsIzhpprJ7JX41DrWd0OtBnE3rVwsN0',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
    {
        'category' => 'Rijndael',
        'subcategory' => 'Android compatibility',
        'detail'   => 'v4.1.2',
        'function' => \&backwards_compatibility,
        'no_ip_check' => 1,
        'pkt' =>
            '+59hIQhS1RlmqYLXNM/hPxtBAQTB5y3UKZq13O+r6qmg+APdQ+HQ' .
            'OI7d4QCsp14s8KJpW8qBzZ/n0aZCFCFdZnvdZeJJVboQu4jo' .
            'QFKZ8mmKwR/5DIO7k3qrXYGxYP0bnHYsih0HIE6CzSHlBGSf' .
            'DJR92YhjYtL4Q',
        'server_positive_output_matches' => [qr/with expire time/],
        'fwknopd_cmdline'  => "LD_LIBRARY_PATH=$lib_dir $valgrind_str " .
            "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'android_legacy_iv_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'fatal'    => $NO
    },
);
