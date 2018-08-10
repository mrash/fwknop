@address_sanitizer = (
    ### this verifies that Google's Address Sanitizer is functioning properly
    ### if fwknop has been compiled with it.
    {
        'category' => 'ASAN',
        'subcategory' => 'Address Sanitizer instrumentation check',
        'detail'   => 'crash verification',
        'function' => \&is_asan_instrumentation_working,
    },
);
