
@build_security_client = (
    {
        'category' => 'build',
        'subcategory' => 'client',
        'detail'   => 'binary exists',
        'function' => \&binary_exists,
        'binary'   => $fwknopCmd,
        'fatal'    => $YES
    },
    {
        'category' => 'build security',
        'subcategory' => 'client',
        'detail'   => 'Position Independent Executable (PIE)',
        'function' => \&pie_binary,
        'binary'   => $fwknopCmd,
    },
    {
        'category' => 'build security',
        'subcategory' => 'client',
        'detail'   => 'stack protected binary',
        'function' => \&stack_protected_binary,
        'binary'   => $fwknopCmd,
    },
    {
        'category' => 'build security',
        'subcategory' => 'client',
        'detail'   => 'fortify source functions',
        'function' => \&fortify_source_functions,
        'binary'   => $fwknopCmd,
    },
    {
        'category' => 'build security',
        'subcategory' => 'client',
        'detail'   => 'read-only relocations',
        'function' => \&read_only_relocations,
        'binary'   => $fwknopCmd,
    },
    {
        'category' => 'build security',
        'subcategory' => 'client',
        'detail'   => 'immediate binding',
        'function' => \&immediate_binding,
        'binary'   => $fwknopCmd,
    },
);

@build_security_server = (
    {
        'category' => 'build',
        'subcategory' => 'server',
        'detail'   => 'binary exists',
        'function' => \&binary_exists,
        'binary'   => $fwknopdCmd,
        'fatal'    => $YES
    },
    {
        'category' => 'build security',
        'subcategory' => 'server',
        'detail'   => 'Position Independent Executable (PIE)',
        'function' => \&pie_binary,
        'binary'   => $fwknopdCmd,
    },
    {
        'category' => 'build security',
        'subcategory' => 'server',
        'detail'   => 'stack protected binary',
        'function' => \&stack_protected_binary,
        'binary'   => $fwknopdCmd,
    },
    {
        'category' => 'build security',
        'subcategory' => 'server',
        'detail'   => 'fortify source functions',
        'function' => \&fortify_source_functions,
        'binary'   => $fwknopdCmd,
    },
    {
        'category' => 'build security',
        'subcategory' => 'server',
        'detail'   => 'read-only relocations',
        'function' => \&read_only_relocations,
        'binary'   => $fwknopdCmd,
    },
    {
        'category' => 'build security',
        'subcategory' => 'server',
        'detail'   => 'immediate binding',
        'function' => \&immediate_binding,
        'binary'   => $fwknopdCmd,
    },
);

@build_security_libfko = (
    {
        'category' => 'build',
        'subcategory' => 'libfko',
        'detail'   => 'binary exists',
        'function' => \&binary_exists,
        'binary'   => $libfko_bin,
        'fatal'    => $YES
    },
    {
        'category' => 'build security',
        'subcategory' => 'libfko',
        'detail'   => 'stack protected binary',
        'function' => \&stack_protected_binary,
        'binary'   => $libfko_bin,
    },
    {
        'category' => 'build security',
        'subcategory' => 'libfko',
        'detail'   => 'fortify source functions',
        'function' => \&fortify_source_functions,
        'binary'   => $libfko_bin,
    },
    {
        'category' => 'build security',
        'subcategory' => 'libfko',
        'detail'   => 'read-only relocations',
        'function' => \&read_only_relocations,
        'binary'   => $libfko_bin,
    },
    {
        'category' => 'build security',
        'subcategory' => 'libfko',
        'detail'   => 'immediate binding',
        'function' => \&immediate_binding,
        'binary'   => $libfko_bin,
    },
);
