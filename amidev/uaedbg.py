#!/usr/bin/env python3

import argparse
import asyncio
import logging
import sys

from amidev.debug.uae import UaeLaunch


def main():
    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)s: %(message)s')
    # logging.getLogger('asyncio').setLevel(logging.DEBUG)

    if sys.platform == 'win32':
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
    else:
        loop = asyncio.get_event_loop()
    # loop.set_debug(True)

    parser = argparse.ArgumentParser(
            description='Run FS-UAE with enabled console debugger.')
    parser.add_argument('-c', '--config', type=str,
                        help='FS-UAE configuration file.')

    args = parser.parse_args()

    uae_args = ['--console_debugger=1', '--stdout=1']
    if args.config:
        uae_args.append(args.config)

    uae = UaeLaunch(loop, *uae_args)
    loop.run_until_complete(uae)
    loop.close()


if __name__ == "__main__":
    main()
