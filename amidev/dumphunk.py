#!/usr/bin/env python

from __future__ import print_function, unicode_literals

import logging
import sys

from amidev.binfmt import hunk


def main():
    logging.basicConfig()

    for path in sys.argv[1:]:
        print('Parsing "%s".' % path)
        print('')

        for h in hunk.ReadFile(path):
            h.dump()
            print('')


if __name__ == '__main__':
    main()
