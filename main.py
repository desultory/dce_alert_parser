#!/usr/bin/env python3

from alert_proxy import AlertProxy

from argparse import ArgumentParser
from logging import getLogger


def main():
    logger = getLogger(__name__)
    logger.setLevel('DEBUG')

    parser = ArgumentParser()
    parser.add_argument('-u', '--user', help="POST authorization header credentials")
    parser.add_argument('-p', '--password', help="POST authorization header credentials")
    parser.add_argument('--address', help="Listen address")
    parser.add_argument('--port', help="Listen port")
    parser.add_argument('--target', help="Target address", required=True)
    args = parser.parse_args()

    kwargs = {arg: value for arg, value in args._get_kwargs() if value is not None}

    proxy = AlertProxy(**kwargs)
    proxy.start()


if __name__ == "__main__":
    main()
