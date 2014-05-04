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

### a few constants
spa_success = 1
spa_failure = 0
spa_sha256  = 3
do_digest   = 1
no_digest   = 0

def main():

    args = parse_cmdline()

    print_hdr()

    spa_payloads = [
        "1716411011200157:cm9vdA:1397329899:2.0.1:1:MTI3LjAuMC4yLHRjcC8yMw",
        "9129760493055133:cm9vdA:1399176256:2.0.1:1:MTI3LjAuMC4yLHRjcC82MDAwMSx1ZHAvNjAwMDE",
        "1716411011200157:cm9vdA:1397329899:2.0.1:1:MTI3LjAuMC4yLHRjcC8yMw:cGFzc3dk",
        "3145808919615481:cm9vdA:1397329998:2.0.1:0:MTI3LjAuMC4yLGVjaG8gZndrbm9wdGVzdCA+IC90bXAvZndrbm9wdGVzdA",
        "1642197848921959:cm9vdA:1397329740:2.0.1:2:MTI3LjAuMC4yLHRjcC8yMg:MTkyLjE2OC4xLjIsMjI",
        "1548062350109656:cm9vdA:1397330450:2.0.1:3:MTI3LjAuMC4yLHRjcC8yMg:2",
        "1414212790438062:cm9vdA:1397329054:2.0.1:4:MTI3LjAuMC4yLHRjcC8yMg:MTkyLjE2OC4xMC4xLDEyMzQ1:1234",
        "3184260168681452:c29tZXVzZXI:1397330288:2.0.1:4:MS4xLjEuMSx0Y3AvMjI:MS4yLjMuNCwxMjM0:10:GboVlHuyiwjxmHbH16vGvlKF",
        "8148229791462660:cm9vdA:1397331007:2.0.1:5:MTI3LjAuMC4yLHRjcC8zNzE3Mg:MTI3LjAuMC4xLDIy",
        "1918702109191551:cm9vdA:1397329052:2.0.1:6:MTI3LjAuMC4yLHRjcC8yMg:MTI3LjAuMC4xLDIy:1234"
    ]

    pkt_id = 1
    payload_num = 0

    for spa_payload in spa_payloads:

        payload_num += 1

        print "# start tests with payload:       ", spa_payload + "\n" \
            "# base64 encoded original payload:", base64.b64encode(spa_payload)

        ### fuzz individual payload fields
        pkt_id = field_fuzzing(args, spa_payload, payload_num, pkt_id)

        ### valid payload tests - all digest types
        pkt_id = valid_payloads(args, spa_payload, payload_num, pkt_id)

        ### invalid digest types
        pkt_id = invalid_digest_types(args, spa_payload, payload_num, pkt_id)

        ### truncated lengths
        pkt_id = truncated_lengths(args, spa_payload, payload_num, pkt_id)

        ### remove chunks of chars out of the original SPA payload
        pkt_id = rm_chunks(args, spa_payload, payload_num, pkt_id)

        ### SPA payloads that are too long
        pkt_id = append_data_to_end(args, spa_payload, payload_num, pkt_id)

        ### additional embedded ':' chars
        pkt_id = embedded_separators(args, spa_payload, payload_num, pkt_id)

        ### non-ascii char tests
        pkt_id = embedded_chars(args, spa_payload, payload_num, pkt_id)

    return

def field_fuzzing(args, spa_payload, payload_num, pkt_id):
    repl_start = 0
    repl_end   = 0
    field_num  = 0
    for idx in range(0, len(spa_payload)):
        if spa_payload[idx] == ':' or idx == len(spa_payload)-1:
            field_num += 1
            if repl_end > 0:
                orig_field = spa_payload[repl_end+1:idx]
            else:
                orig_field = spa_payload[repl_end:idx]

            repl_start = repl_end
            repl_end = idx

            ### now generate fuzzing data for this field
            for c in range(0, 3) + range(33, 47) + range(65, 67) + range(127, 130) + range(252, 256):
                for l in [1, 2, 3, 4, 5, 6, 10, 14, 15, 16, 17, 24, 31, 32, 33, \
                        63, 64, 127, 128, 129, 150, 220, 230, 254, 255, 256, 257, 258]:

                    fuzzing_field = ''
                    require_b64 = orig_field.isdigit()

                    for n in range(0, l):
                        fuzzing_field += chr(c)

                    new_payloads = [
                            spa_payload[:repl_start],  ### for payloads without original field
                            spa_payload[:repl_start],  ### prepend fuzzing field with original
                            spa_payload[:repl_start]   ### append fuzzing field to original
                    ]

                    if field_num > 1:
                        for i in range(0, len(new_payloads)):
                            new_payloads[i] += ':'

                    if idx == len(spa_payload)-1:
                        field_variants(new_payloads, fuzzing_field, orig_field, require_b64)
                    else:
                        if field_num == 1 or field_num in range(3, 6):
                            ### fields: rand val, time stamp, version, and SPA type
                            field_variants(new_payloads, fuzzing_field, orig_field, False)
                        elif field_num == 2: ### user field
                            field_variants(new_payloads, fuzzing_field, orig_field, True)
                        else:
                            field_variants(new_payloads, fuzzing_field, orig_field, require_b64)

                        for i in range(0, len(new_payloads)):
                            new_payloads[i] += spa_payload[repl_end:]

                    for s in new_payloads:
                        print str(pkt_id), str(spa_failure), str(do_digest), \
                                str(spa_sha256), base64.b64encode(s)
                        pkt_id += 1

    return pkt_id

def field_variants(new_payloads, fuzzing_field, orig_field, require_b64):
    if require_b64:
        decoded_orig_field = spa_base64_decode(orig_field)
        new_payloads[0] += base64.b64encode(fuzzing_field)
        new_payloads[1] += base64.b64encode(fuzzing_field+decoded_orig_field)
        new_payloads[2] += base64.b64encode(decoded_orig_field+fuzzing_field)
    else:
        new_payloads[0] += fuzzing_field
        new_payloads[1] += fuzzing_field+orig_field
        new_payloads[2] += orig_field+fuzzing_field
    return

def spa_base64_decode(b64str):
    ### account for how fwknop strips '=' chars
    remainder = len(b64str) % 4
    if remainder != 0:
        for i in range(0, remainder):
            b64str += '='

    return base64.b64decode(b64str)

def valid_payloads(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " valid payload + valid digest types..."
    for digest_type in range(0, 6):
        print str(pkt_id), str(spa_success), str(do_digest), \
                str(digest_type), base64.b64encode(spa_payload)
        pkt_id += 1
    return pkt_id

def invalid_digest_types(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " invalid digest types..."
    for digest_type in [-1, 6, 7]:
        print str(pkt_id), str(spa_success), str(do_digest), \
                str(digest_type), base64.b64encode(spa_payload)
        pkt_id += 1
    return pkt_id

def truncated_lengths(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " truncated lengths..."
    for l in range(1, len(spa_payload)):
        print str(pkt_id), str(spa_failure), str(do_digest), \
                str(spa_sha256), base64.b64encode(spa_payload[:l])
        pkt_id += 1
    for l in range(1, len(spa_payload)):
        print str(pkt_id), str(spa_failure), str(do_digest), \
                str(spa_sha256), base64.b64encode(spa_payload[l:])
        pkt_id += 1

    return pkt_id

def rm_chunks(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " splice blocks of chars..."
    for bl in range(1, 20):
        for l in range(0, len(spa_payload)):
            new_payload = spa_payload[:l] + spa_payload[l+bl:]
            print str(pkt_id), str(spa_failure), str(do_digest), \
                    str(spa_sha256), base64.b64encode(new_payload)
            pkt_id += 1
    return pkt_id

def append_data_to_end(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " payloads too long..."
    for l in [1, 10, 50, 127, 128, 129, 200, 399, \
            400, 401, 500, 800, 1000, 1023, 1024, 1025, \
            1200, 1499, 1500, 1501, 2000]:
        for non_ascii in range(0, 5) + range(127, 130) + range(252, 256):
            new_payload = spa_payload
            for p in range(0, l):
                new_payload += chr(non_ascii)
            print str(pkt_id), str(spa_failure), str(do_digest), \
                    str(spa_sha256), base64.b64encode(new_payload)
            pkt_id += 1
    return pkt_id

def embedded_separators(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " additional embedded : chars..."
    for pos in range(0, len(spa_payload)):
        if spa_payload[pos] == ':':
            continue
        new_payload = list(spa_payload)
        new_payload[pos] = ':'
        print str(pkt_id), str(spa_failure), str(do_digest), \
                str(spa_sha256), base64.b64encode(''.join(new_payload))
        pkt_id += 1
    return pkt_id

def embedded_chars(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " non-ascii char tests..."
    for pos in range(0, len(spa_payload)):
        for non_ascii in range(0, 31) + range(44, 48) + range(127, 131) + range(253, 255):
            new_payload = list(spa_payload)
            new_payload[pos] = chr(non_ascii)
            ### write out the fuzzing line
            print str(pkt_id), str(spa_failure), str(do_digest), \
                    str(spa_sha256), base64.b64encode(''.join(new_payload))
            pkt_id += 1
    return pkt_id

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
