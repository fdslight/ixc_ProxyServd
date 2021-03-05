#!/usr/bin/env python3

import libProxyServd.session as session


class auth(session.auth_base):
    def myinit(self, *args, **kwargs):
        pass

    def do_auth(self, user_id: bytes):
        pass

    def send_to_client(self, user_id: bytes, data_len: int):
        pass

    def recv_from_client(self, user_id: bytes, data_len: int):
        pass
