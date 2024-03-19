#!/usr/bin/env python3

from dce_alert import DCEAlert

from logging import getLogger


def main():
    logger = getLogger(__name__)
    logger.setLevel('DEBUG')
    with open('test.xml') as f:
        xml = f.read()

    alert = DCEAlert(xml)
    print(alert.to_json())


if __name__ == "__main__":
    main()
