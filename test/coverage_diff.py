#!/usr/bin/env python

#
# This script is executed by test-fwknop.pl in --enable-profile-coverage mode
# to show additions of code coverage in gcov/lcov output.
#

import re
import argparse
import os

def main():

    args = parse_cmdline()

    ### the test suite writes final coverage info to this path
    ### in the output directory.
    final_lcov_file = "lcov_coverage_final.info"

    old_lcov_file = args.old_lcov_file
    new_lcov_file = args.new_lcov_file

    if args.old_lcov_dir:
        old_lcov_file = args.old_lcov_dir + "/" + final_lcov_file

    if args.new_lcov_dir:
        new_lcov_file = args.new_lcov_dir + "/" + final_lcov_file

    if not os.path.exists(old_lcov_file):
        print "[*] old coverage file does not exist: %s" % old_lcov_file
        return 1

    if not os.path.exists(new_lcov_file):
        print "[*] new coverage file does not exist: %s" % new_lcov_file
        return 1

    old_zero_coverage = extract_zero_coverage(old_lcov_file)
    new_zero_coverage = extract_zero_coverage(new_lcov_file)

    ### diff the two dictionaries
    print "[+] New coverage:"
    for f in old_zero_coverage:
        printed_file = 0
        if f in new_zero_coverage:
            for ctype in old_zero_coverage[f]:
                for val in sorted(old_zero_coverage[f][ctype]):
                    if val not in new_zero_coverage[f][ctype]:
                        if not printed_file:
                            print "[+] Coverage: " + f
                            printed_file = 1
                        print "[+] new '" + ctype + "' coverage: " + val

    print "\n[-] Missing coverage from the previous run:"
    for f in new_zero_coverage:
        printed_file = 0
        if f in old_zero_coverage:
            for ctype in new_zero_coverage[f]:
                for val in sorted(new_zero_coverage[f][ctype]):
                    if val not in old_zero_coverage[f][ctype]:
                        if not printed_file:
                            print "[-] Coverage: " + f
                            printed_file = 1
                        print "[-] missing '" + ctype + "' coverage: " + val

def extract_zero_coverage(lcov_file):

    zero_coverage = {}

    ### populate old lcov output for functions/lines that were called
    ### zero times
    with open(lcov_file, 'r') as f:
        current_file = ''
        for line in f:
            line = line.strip()

            m = re.search('SF:(\S+)', line)
            if m and m.group(1):
                current_file = m.group(1)
                zero_coverage[current_file] = {}
                zero_coverage[current_file]['fcns'] = {}
                zero_coverage[current_file]['lines'] = {}
                continue

            if current_file:
                ### look for functions that were never called
                m = re.search('^FNDA:0,(\S+)', line)
                if m and m.group(1):
                    zero_coverage[current_file]['fcns'][m.group(1) + '()'] = ''
                    continue

                ### look for lines that were never called
                m = re.search('^DA:(\d+),0', line)
                if m and m.group(1):
                    zero_coverage[current_file]['lines'][m.group(1)] = ''

    return zero_coverage

def parse_cmdline():

    ### parse command line args
    parser = argparse.ArgumentParser()

    parser.add_argument("-o", "--old-lcov-file", type=str, \
            help="old lcov file", default="output.last/lcov_coverage_final.info")
    parser.add_argument("-n", "--new-lcov-file", type=str, \
            help="new lcov file", default="output/lcov_coverage_final.info")
    parser.add_argument("-O", "--old-lcov-dir", type=str, \
            help="old lcov file", default="")
    parser.add_argument("-N", "--new-lcov-dir", type=str, \
            help="new lcov file", default="")

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    main()
