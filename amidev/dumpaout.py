#!/usr/bin/env python3

import logging
import sys

from amidev.binfmt import aout


def main():
    logging.basicConfig()

    for path in sys.argv[1:]:
        obj = aout.Aout()
        obj.read(path)
        obj.dump()


if __name__ == '__main__':
    main()
