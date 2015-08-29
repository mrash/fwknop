
# Fuzzing fwknop With American Fuzzy Lop (AFL)

## Quick Start

To get going with AFL fuzzing against fwknop:

    $ cd fwknop.git/test/afl/
    $ ./compile/afl-compile.sh
    $ ./fuzzing-wrappers/spa-pkts.sh

Fuzzing results will be placed in fuzzing-output/server-conf.out/. For more
information, read on.

## Introduction

The fwknop project supports various fuzzing strategies, and one of the most
important is usage of the 'American Fuzzy Lop' (AFL) fuzzer written by Michal
Zalewski (see: [http://lcamtuf.coredump.cx/afl/]). Because AFL is not designed to
handle encryption schemes (see the README included in the AFL sources for more
information on this), a special *--enable-afl-fuzzing* command line switch is
available in the fwknop autoconf configure script. This argument allows
encryption and base64 encoding to be bypassed when feeding SPA packet data to
fwknopd via stdin. It is this feature that enables AFL fuzzing, and is analogous
to the *libpng-nocrc.patch* patch included in the AFL sources. The corresponding
commit that enables this functionality in fwknop is aaa44656bcfcb705d80768a7b9aa0d45a0e55e21
(see: [https://github.com/mrash/fwknop/commit/aaa44656bcfcb705d80768a7b9aa0d45a0e55e21])

## AFL Wrappers

The top level directory contains enabling scripts in order to make it easy to
fuzz fwknop with AFL. It is assumed that AFL is installed and in your path. The
files are in this directory are organized as follows:

 * *fuzzing-wrappers/*

  Directory that contains wrapper scripts for running AFL against fwknop. All
  interaction with AFL should be done with these scripts, and they should be executed
  from the test/afl/ directory, e.g. *./fuzzing-wrappers/client-rc.sh*.

  There are four areas in fwknop that are fuzzed:
    1. SPA packet encoding/decoding (*./fuzzing-wrappers/spa-pkts.sh*)
    2. server access.conf parsing (*./fuzzing-wrappers/server-access.sh*)
    3. server fwknopd.conf parsing (*./fuzzing-wrappers/server-conf.sh*)
    4. client fwknoprc file parsing. (*./fuzzing-wrappers/client-rc.sh*)

 * *fuzzing-wrappers/helpers/*

  Directory for helper scripts that are used by the fuzzing wrappers to ensure
  that fwknop is compiled properly for AFL support and is ready for fuzzing cycles.

 * *test-cases/*

  Directory for AFL test cases used by the wrapper scripts.

 * *compile/*

  Directory for compilation scripts to ensure fwknop is compiled underneath afl-gcc.

 * *fuzzing-output/*

  Results directory that is made underneath an AFL fuzzing cycle.

## Complete Example

To fuzz the SPA packet encoding/decoding routines, the *fuzzing-wrappers/spa-pkts.sh*
script will kick things off. This assumes that fwknop has been compiled with AFL
support with the *compile/afl-compile.sh* script:

    $ ./fuzzing-wrappers/spa-pkts.sh
    ...
    + LD_LIBRARY_PATH=../../lib/.libs afl-fuzz -t 1000 -i test-cases/spa-pkts -o fuzzing-output/spa-pkts.out ../../server/.libs/fwknopd -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t
    afl-fuzz 0.64b (Nov 22 2014 13:04:11) by <lcamtuf@google.com>
    [+] You have 1 CPU cores and 2 runnable tasks (utilization: 200%).
    [*] Checking core_pattern...
    [*] Setting up output directories...
    [+] Output directory exists but deemed OK to reuse.
    [*] Deleting old session data...
    [+] Output dir cleanup successful.
    [*] Scanning 'test-cases/spa-pkts'...
    [*] Creating hard links for all input files...
    [*] Validating target binary...
    [*] Attempting dry run with 'id:000000,orig:spa.start'...
    [*] Spinning up the fork server...
    [+] All right - fork server is up.
    ...

Then the familiar AFL status screen is displayed:

![alt text][AFL-status-screen]

[AFL-status-screen]: https://github.com/mrash/fwknop/raw/master/test/afl/doc/AFL_status_screen.png "AFL Fuzzing SPA Packets"

## SPA Packet Helper Script

Here is an example of what fwknopd produces when compiled for AFL support when
a dummy SPA packet is provided in non-encoded/encrypted from via fwknopd's
stdin. This uses the *fwknopd-stdin-test.sh* helper script:

    $ ./fuzzing-wrappers/helpers/fwknopd-stdin-test.sh
    + SPA_PKT=1716411011200157:root:1397329899:2.0.1:1:127.0.0.2,tcp/22:AAAAA
    + LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t
    + echo -n 1716411011200157:root:1397329899:2.0.1:1:127.0.0.2,tcp/22:AAAAA
    Warning: REQUIRE_SOURCE_ADDRESS not enabled for access stanza source: 'ANY'
    SPA Field Values:
    =================
       Random Value: 1716411011200157
           Username: root
          Timestamp: 1397329899
        FKO Version: 2.0.1
       Message Type: 1 (Access msg)
     Message String: 127.0.0.2,tcp/22
         Nat Access: <NULL>
        Server Auth: <NULL>
     Client Timeout: 0
        Digest Type: 3 (SHA256)
          HMAC Type: 0 (None)
    Encryption Type: 1 (Rijndael)
    Encryption Mode: 2 (CBC)
       Encoded Data: 1716411011200157:root:1397329899:2.0.1:1:127.0.0.2,tcp/22
    SPA Data Digest: AAAAA
               HMAC: <NULL>
     Final SPA Data: 200157:root:1397329899:2.0.1:1:127.0.0.2,tcp/22:AAAAA

    SPA packet decode: Success
