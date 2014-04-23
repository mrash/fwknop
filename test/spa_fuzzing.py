#!/usr/bin/env python
#
# Purpose: This script generates SPA packet payloads that are designed to
#          act as fuzzer against libfko SPA decoding routines.
#
# Fuzzing file format:
#
#   <pkt_ID> <status: success|fail> <digest: yes|no> <digest type> <base64_SPA_payload>
#
# SPA payload format (before:
#
#   <rand_num>:<user>:<timestamp>:<version>:<spa_msg_type>:<access_request
#
# Example SPA payload (after inner base64 encoding):
#
#   1716411011200157:cm9vdA:1397329899:2.0.1:1:MTI3LjAuMC4yLHRjcC8yMw
#

import base64
import argparse

def main():

    ### a few constants
    spa_success = 1
    spa_failure = 0
    spa_sha256  = 3
    do_digest   = 1
    no_digest   = 0

    args = parse_cmdline()

    print_hdr()

    spa_payload = "1716411011200157:cm9vdA:1397329899:2.0.1:1:MTI3LjAuMC4yLHRjcC8yMw"

    pkt_id = 1

    ### valid payload tests - all digest types
    print "# valid payloads..."
    for digest_type in range(0, 6):
        print str(pkt_id), str(spa_success), str(do_digest), \
                str(digest_type), base64.b64encode(spa_payload)
        pkt_id += 1

    ### invalid digest types
    print "# invalid digest types..."
    for digest_type in [-1, 6, 7]:
        print str(pkt_id), str(spa_success), str(do_digest), \
                str(digest_type), base64.b64encode(spa_payload)
        pkt_id += 1

    ### truncated lengths
    print "# truncated lengths..."
    for l in range(1, len(spa_payload)):
        print str(pkt_id), str(spa_failure), str(do_digest), \
                str(spa_sha256), base64.b64encode(spa_payload[:l])
        pkt_id += 1
    for l in range(1, len(spa_payload)):
        print str(pkt_id), str(spa_failure), str(do_digest), \
                str(spa_sha256), base64.b64encode(spa_payload[l:])
        pkt_id += 1

    ### SPA payloads that are too long
    print "# payloads too long..."
    for l in [1, 10, 50, 127, 128, 129, 200, 399, \
            400, 401, 500, 800, 1000, 1023, 1024, 1025, \
            1200, 1499, 1500, 1501, 2000]:
        for non_ascii in range(0, 5) + range(127, 130) + range(252, 255):
            new_payload = spa_payload
            for p in range(0, l):
                new_payload += chr(non_ascii)
            print str(pkt_id), str(spa_failure), str(do_digest), \
                    str(spa_sha256), base64.b64encode(new_payload)
            pkt_id += 1

    ### additional embedded ':' chars
    print "# additional embedded : chars..."
    for pos in range(0, len(spa_payload)):
        if spa_payload[pos] == ':':
            continue
        new_payload = list(spa_payload)
        new_payload[pos] = ':'
        print str(pkt_id), str(spa_failure), str(do_digest), \
                str(spa_sha256), base64.b64encode(''.join(new_payload))
        pkt_id += 1

    ### non-ascii char tests
    print "# non-ascii char tests..."
    for pos in range(0, len(spa_payload)):
        for non_ascii in range(0, 31) + range(127, 255):
            new_payload = list(spa_payload)
            new_payload[pos] = chr(non_ascii)
            ### write out the fuzzing line
            print str(pkt_id), str(spa_failure), str(do_digest), \
                    str(spa_sha256), base64.b64encode(''.join(new_payload))
            pkt_id += 1

    return

def print_hdr():
    print "# <pkt_ID> <status: success|fail> <digest: yes|no> <digest type> <base64_SPA_payload>"
    return

def parse_cmdline():

    ### parse command line args
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--max-packet-count", type=int, help="packet count", default=1000000)

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    main()
