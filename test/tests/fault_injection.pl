@fault_injection = (
    {
        'category' => 'fault injection',
        'subcategory' => 'libfko',
        'detail'   => 'acquire FKO context',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'faultinjection',
        'wrapper_script'  => $wrapper_exec_script,
        'wrapper_binary'  => 'fko_fault_injection',
    },
    {
        'category' => 'fault injection',
        'subcategory' => 'libfko',
        'detail'   => 'acquire FKO context (with valgrind)',
        'function' => \&fko_wrapper_exec,
        'wrapper_compile' => 'faultinjection',
        'wrapper_script'  => $wrapper_exec_script_valgrind,
        'wrapper_binary'  => 'fko_fault_injection',
    },

);
