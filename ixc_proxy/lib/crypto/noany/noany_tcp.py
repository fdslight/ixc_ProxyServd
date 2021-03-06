#!/usr/bin/env python3

from ixc_proxy import lib as tunnel


class encrypt(tunnel.builder):
    def __init__(self):
        super().__init__(tunnel.MIN_FIXED_HEADER_SIZE)


class decrypt(tunnel.parser):
    def __init__(self):
        super().__init__(tunnel.MIN_FIXED_HEADER_SIZE)
