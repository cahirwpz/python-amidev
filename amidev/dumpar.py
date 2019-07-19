#!/usr/bin/env python3

import logging
import sys

from amidev.binfmt import ar


def main():
    logging.basicConfig()

    for path in sys.argv[1:]:
        print('%s:' % path)
        for num, entry in enumerate(ar.ReadFile(path), start=1):
            print('%5d:' % num, entry.name, '(length: %d)' % len(entry.data))
        print('')


if __name__ == '__main__':
    main()
