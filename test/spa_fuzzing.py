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

    args = parse_cmdline()

    print_hdr()

    spa_payload = "1716411011200157:cm9vdA:1397329899:2.0.1:1:MTI3LjAuMC4yLHRjcC8yMw"

    pkt_id = 1

    #### non-ascii char tests
    for pos in range(0, len(spa_payload)):
        for non_ascii in range(0, 31) + range(127, 255):
            new_payload = list(spa_payload)
            new_payload[pos] = chr(non_ascii)
            ### write out the fuzzing line
            print str(pkt_id) + " 0 1 3 " + base64.b64encode(''.join(new_payload))
            pkt_id += 1

    # for c in list(spa_payload):
        # print c

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
