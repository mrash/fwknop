@fault_injection = (
    {
        'category' => 'fault injection',
        'subcategory' => 'libfko',
        'detail'   => 'acquire FKO context',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'faultinjection',
        'wrapper_script'  => $wrapper_exec_script,
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_fault_injection',
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'libfko',
        'detail'   => 'acquire FKO context (with valgrind)',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'faultinjection',
        'wrapper_script'  => $wrapper_exec_script_valgrind,
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_fault_injection',
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run libc/mm/*',
        'detail'   => 'acquire FKO context',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'all',
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_basic',
        'fiu_run' => $YES,
        'fiu_injection_style' => 'enable_random name=libc/mm/*,probability=0.05',
        'fiu_iterations' => 1000
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run libc/str/strdup',
        'detail'   => 'acquire FKO context',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'all',
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_basic',
        'fiu_run' => $YES,
        'fiu_injection_style' => 'enable_random name=libc/str/strdup,probability=0.05',
        'fiu_iterations' => 1000
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run posix/io/rw/*',
        'detail'   => 'acquire FKO context',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'all',
        'wrapper_binary'  => cwd() . '/' . $fko_wrapper_dir . '/fko_basic',
        'fiu_run' => $YES,
        'fiu_injection_style' => 'enable_random name=posix/io/rw/*,probability=0.05',
        'fiu_iterations' => 1000
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'fiu-run libc/mm/*',
        'detail'   => 'client',
        'function' => \&fiu_run_fault_injection,
        'cmdline' => "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file --no-save-args $verbose_str",
        'fiu_injection_style' => 'enable_random name=libc/mm/*,probability=1',
        'fiu_iterations' => 10
    },

);
