#!/usr/bin/env python3

import os
import pywind.evtframework.handlers.handler as handler


class tundev(handler.handler):
    __devname = None
    __sent = None

    @property
    def proxy(self):
        return self.dispatcher.proxy

    def init_func(self, creator_fd, devname: str):
        fd = self.proxy.tundev_open(devname)
        if fd < 0:
            raise SystemError("cannot create tun device")

        self.__devname = devname
        self.__sent = []

        self.set_fileno(fd)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def evt_read(self):
        for i in range(10):
            try:
                read_data = os.read(self.fileno, 4096)
            except BlockingIOError:
                break

    def evt_write(self):
        if not self.__sent: self.remove_evt_write(self.fileno)

    def error(self):
        pass

    def delete(self):
        self.unregister(self.fileno)
        self.proxy.tundev_close(self.fileno, self.__devname)

    def send_msg(self, message: bytes):
        self.__sent.append(message)
        self.add_evt_write(self.fileno)
