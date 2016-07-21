#!/usr/bin/env python

import sys

if __name__ == '__main__':
    with open('VERSION', 'r') as f:
        v_major, v_minor, v_patch = [int(x) for x in f.read().strip().split('.')]
    if len(sys.argv) > 1:
        if sys.argv[1] == 'major':
            v_major += 1
            v_minor = 0
            v_patch = 0
        elif sys.argv[1] == 'minor':
            v_minor += 1
            v_patch = 0
        else:
            v_patch += 1
    else:
        v_patch += 1
    with open('VERSION', 'w+') as f:
        f.write('.'.join([str(x) for x in (v_major, v_minor, v_patch)]))
