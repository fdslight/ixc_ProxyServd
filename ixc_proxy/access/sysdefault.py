#!/usr/bin/env python3

import ixc_proxy.access._access as _access
import os, json


class access(_access.access):
    __users = None

    def load_configs(self):
        my_dir = os.path.dirname(__file__)
        config_path = "%s/../../ixc_configs/access.json" % my_dir

        with open(config_path, "r") as f:
            users_info = json.loads(f.read())

        for dic in users_info:
            username = dic["username"]
            passwd = dic["password"]

            session_id = self.gen_session_id(username, passwd)
            self.__users[session_id] = username

    def init(self):
        self.__users = {}
        self.load_configs()

    def handle_recv(self, fileno, session_id, address, data_len):
        if session_id not in self.__users: return False
        if not self.session_exists(session_id):
            self.add_session(fileno, self.__users[session_id], session_id, address)

        return True

    def handle_send(self, session_id, data_len):
        if not self.session_exists(session_id): return False

        return True

    def handle_close(self, session_id):
        pass

    def handle_access_loop(self):
        pass

    def handle_user_change_signal(self):
        self.__users = {}
        self.load_configs()

    def user_exists(self, user_id: bytes):
        return user_id in self.__users
