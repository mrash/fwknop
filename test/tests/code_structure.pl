
@code_structure_errstr = (
    {
        'category' => 'code structure',
        'subcategory' => 'error strings',
        'detail'   => 'all error codes handled',
        'function' => \&code_structure_fko_error_strings,
    },
    {
        'category' => 'code structure',
        'subcategory' => 'chars',
        'detail'   => 'search for non-ascii chars',
        'function' => \&code_structure_search_sources_for_non_ascii_chars,
    },
);
