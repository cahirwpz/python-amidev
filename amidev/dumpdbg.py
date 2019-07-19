#!/usr/bin/env python3

import logging
import sys

from amidev.debug.info import DebugInfo


def main():
    logging.basicConfig()

    for path in sys.argv[1:]:
        print('Parsing "%s".' % path)
        print('')

        di = DebugInfo()
        di.fromFile(path)
        di.dump()

        print('')


if __name__ == '__main__':
    main()
