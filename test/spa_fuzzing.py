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

        ### valid payload tests - all digest types
        pkt_id = valid_payloads(args, spa_payload, payload_num, pkt_id)

        ### fuzz individual payload fields
        pkt_id = field_fuzzing(args, spa_payload, payload_num, pkt_id)

        ### invalid digest types
        pkt_id = invalid_digest_types(args, spa_payload, payload_num, pkt_id)

        ### truncated lengths
        pkt_id = truncated_lengths(args, spa_payload, payload_num, pkt_id)

        ### remove chunks of chars out of the original SPA payload
        pkt_id = rm_chunks(args, spa_payload, payload_num, pkt_id)

        ### SPA payloads that are too long
        pkt_id = data_extensions(args, spa_payload, payload_num, pkt_id)

        ### additional embedded ':' chars
        pkt_id = embedded_separators(args, spa_payload, payload_num, pkt_id)

        ### non-ascii char tests
        pkt_id = embedded_chars(args, spa_payload, payload_num, pkt_id)

    return

def field_fuzzing(args, spa_payload, payload_num, pkt_id):

    print "# payload " + str(payload_num) + " (" + spa_payload + ") field fuzzing..."

    repl_start = 0
    repl_end   = 0
    field_num  = 0
    for idx in range(0, len(spa_payload)):
        if spa_payload[idx] == ':' or idx == len(spa_payload)-1:
            field_num += 1
            if repl_end > 0:
                if idx == len(spa_payload)-1:
                    orig_field = spa_payload[repl_end+1:]
                else:
                    orig_field = spa_payload[repl_end+1:idx]
            else:
                orig_field = spa_payload[repl_end:idx]

            repl_start = repl_end
            repl_end = idx

            decoded = orig_field
            if is_field_b64(orig_field, field_num):
                decoded = spa_base64_decode(orig_field)

            ### first round of fuzzing for this field is to take the original
            ### field and permute it in various ways

            ### truncation
            for l in range(1, len(decoded)):
                pkt_id = write_fuzzing_payload(field_num, decoded[:l], \
                    orig_field, repl_start, repl_end, spa_payload, \
                    pkt_id, idx)
                pkt_id = write_fuzzing_payload(field_num, decoded[l:], \
                    orig_field, repl_start, repl_end, spa_payload, \
                    pkt_id, idx)

            ### remove chunks
            for bl in range(1, len(decoded)):
                for l in range(0, bl):
                    fuzzing_field = decoded[:l] + decoded[l+bl:]
                    pkt_id = write_fuzzing_payload(field_num, fuzzing_field, \
                        orig_field, repl_start, repl_end, spa_payload, \
                        pkt_id, idx)

            ### append/prepend data
            for l in [1, 10, 50, 127, 128, 129, 200, 399, \
                    400, 401, 500, 800, 1000, 1023, 1024, 1025, \
                    1200, 1499, 1500, 1501, 2000]:
                for non_ascii in range(0, 5) + range(127, 130) + range(252, 256):
                    new_data = ''
                    for p in range(0, l):
                        new_data += chr(non_ascii)
                    pkt_id = write_fuzzing_payload(field_num, decoded + new_data, \
                        orig_field, repl_start, repl_end, spa_payload, \
                        pkt_id, idx)
                    pkt_id = write_fuzzing_payload(field_num, new_data + decoded, \
                        orig_field, repl_start, repl_end, spa_payload, \
                        pkt_id, idx)

            ### embedded separators
            for pos in range(0, len(decoded)):
                fuzzing_field = list(decoded)
                fuzzing_field[pos] = ':'
                pkt_id = write_fuzzing_payload(field_num, str(fuzzing_field), \
                    orig_field, repl_start, repl_end, spa_payload, \
                    pkt_id, idx)

            ### embedded chars
            for pos in range(0, len(decoded)):
                for c in range(0, 31) + range(44, 48) + range(127, 131) + range(253, 255):
                    fuzzing_field = list(decoded)
                    fuzzing_field[pos] = chr(c)
                    pkt_id = write_fuzzing_payload(field_num, str(fuzzing_field), \
                        orig_field, repl_start, repl_end, spa_payload, \
                        pkt_id, idx)

            ### now generate fuzzing data for this field
            for c in range(0, 3) + range(33, 47) + range(65, 67) + range(127, 130) + range(252, 256):
                for l in [1, 2, 3, 4, 5, 6, 10, 14, 15, 16, 17, 24, 31, 32, 33, \
                        63, 64, 127, 128, 129, 150, 220, 230, 254, 255, 256, 257, 258]:

                    fuzzing_field = ''
                    for n in range(0, l):
                        fuzzing_field += chr(c)
                    pkt_id = write_fuzzing_payload(field_num, fuzzing_field, \
                            orig_field, repl_start, repl_end, spa_payload, \
                            pkt_id, idx)

    return pkt_id

def write_fuzzing_payload(field_num, fuzzing_field, orig_field, \
        repl_start, repl_end, spa_payload, pkt_id, idx):

    new_payloads = [
            spa_payload[:repl_start],  ### replace original field with fuzzing field
            spa_payload[:repl_start],  ### prepend fuzzing field to original
            spa_payload[:repl_start]   ### append fuzzing field to original
    ]

    if field_num > 1:
        for i in range(0, len(new_payloads)):
            new_payloads[i] += ':'

    field_variants(new_payloads, fuzzing_field, \
            orig_field, is_field_b64(orig_field, field_num))

    if idx != len(spa_payload)-1:
        for i in range(0, len(new_payloads)):
            new_payloads[i] += spa_payload[repl_end:]

    for s in new_payloads:
        print str(pkt_id), str(spa_failure), str(do_digest), \
                str(spa_sha256), base64.b64encode(s)
        pkt_id += 1

    return pkt_id

def is_field_b64(orig_field, field_num):

    ### this accounts for SPA packets with an optional client defined
    ### firewall timeout field at the end
    require_b64 = not orig_field.isdigit()

    if field_num == 1 or field_num in range(3, 6):
        ### fields: rand val, time stamp, version, and SPA type
        require_b64 = False
    elif field_num == 2:  ### user field
        require_b64 = True

    return require_b64

def field_variants(new_payloads, fuzzing_field, orig_field, require_b64):
    if require_b64:
        decoded_orig_field = spa_base64_decode(orig_field)
        new_payloads[0] += spa_base64_encode(fuzzing_field)
        new_payloads[1] += spa_base64_encode(fuzzing_field+decoded_orig_field)
        new_payloads[2] += spa_base64_encode(decoded_orig_field+fuzzing_field)
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

def spa_base64_encode(nonb64str):
    ### strip '=' chars like fwknop does
    return base64.b64encode(nonb64str).replace('=', '')

def valid_payloads(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " (" + spa_payload + ") valid payload + valid digest types..."
    for digest_type in range(0, 6):
        print str(pkt_id), str(spa_success), str(do_digest), \
                str(digest_type), base64.b64encode(spa_payload)
        pkt_id += 1
    return pkt_id

def invalid_digest_types(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " (" + spa_payload + ") invalid digest types..."
    for digest_type in [-1, 6, 7]:
        print str(pkt_id), str(spa_success), str(do_digest), \
                str(digest_type), base64.b64encode(spa_payload)
        pkt_id += 1
    return pkt_id

def truncated_lengths(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " (" + spa_payload + ") truncated lengths..."
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
    print "# payload " + str(payload_num) + " (" + spa_payload + ") splice blocks of chars..."
    for bl in range(1, 20):
        for l in range(0, len(spa_payload)):
            new_payload = spa_payload[:l] + spa_payload[l+bl:]
            print str(pkt_id), str(spa_failure), str(do_digest), \
                    str(spa_sha256), base64.b64encode(new_payload)
            pkt_id += 1
    return pkt_id

def data_extensions(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " (" + spa_payload + ") payloads too long..."
    for l in [1, 10, 50, 127, 128, 129, 200, 399, \
            400, 401, 500, 800, 1000, 1023, 1024, 1025, \
            1200, 1499, 1500, 1501, 2000]:
        for non_ascii in range(0, 5) + range(127, 130) + range(252, 256):
            new_data = ''
            for p in range(0, l):
                new_data += chr(non_ascii)
            ### append
            print str(pkt_id), str(spa_failure), str(do_digest), \
                    str(spa_sha256), base64.b64encode(spa_payload + new_data)
            ### prepend
            print str(pkt_id), str(spa_failure), str(do_digest), \
                    str(spa_sha256), base64.b64encode(new_data + spa_payload)
            pkt_id += 2
    return pkt_id

def embedded_separators(args, spa_payload, payload_num, pkt_id):
    print "# payload " + str(payload_num) + " (" + spa_payload + ") additional embedded : chars..."
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
    print "# payload " + str(payload_num) + " (" + spa_payload + ") non-ascii char tests..."
    for pos in range(0, len(spa_payload)):
        for c in range(0, 31) + range(44, 48) + range(127, 131) + range(253, 255):
            new_payload = list(spa_payload)
            new_payload[pos] = chr(c)
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
