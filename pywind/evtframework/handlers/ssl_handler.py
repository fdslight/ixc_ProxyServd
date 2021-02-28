#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import ssl


class ssl_handler(tcp_handler.tcp_handler):
    __creator_fd = None
    __ssl_handshake_ok = None
    __ssl_on = None
    __server_side = None

    def init_func(self, creator_fd, *args, **kwargs):
        self.__creator_fd = creator_fd
        self.__ssl_handshake_ok = False

        return self.ssl_init(*args, **kwargs)

    def set_ssl_on(self):
        self.__ssl_on = True

    def set_as_server_side(self):
        self.__server_side = True

    @property
    def creator(self):
        return self.__creator_fd

    def ssl_init(self, *args, **kwargs):
        """初始化SSL,重写这个方法
        :param args:
        :param kwargs:
        :return fileno:
        """
        return -1

    def evt_read(self):
        if self.__server_side:
            if not self.__ssl_on:
                super().evt_read()
                return
            ''''''
        else:
            if not self.is_conn_ok():
                super().evt_read()
                return
            ''''''

        if not self.__ssl_handshake_ok:
            self.__do_ssl_handshake()

        if not self.__ssl_handshake_ok: return

        try:
            super().evt_read()
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except ssl.SSLWantReadError:
            if self.reader.size() > 0:
                self.tcp_readable()
        except ssl.SSLZeroReturnError:
            if self.reader.size() > 0:
                self.tcp_readable()
            if self.handler_exists(self.fileno): self.delete_handler(self.fileno)

    def evt_write(self):
        if self.__server_side:
            if not self.__ssl_on:
                super().evt_write()
                return
            ''''''
        else:
            if not self.is_conn_ok():
                super().evt_write()
                return
            ''''''

        if not self.__ssl_handshake_ok:
            self.remove_evt_write(self.fileno)
            self.__do_ssl_handshake()

        if not self.__ssl_handshake_ok: return
        try:
            super().evt_write()
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except ssl.SSLEOFError:
            self.delete_handler(self.fileno)
        except ssl.SSLError:
            self.delete_handler(self.fileno)

    def ssl_handshake_ok(self):
        """握手成功后的处理,重写这个方法
        :return:
        """
        pass

    def __do_ssl_handshake(self):
        try:
            self.socket.do_handshake()
            self.__ssl_handshake_ok = True
            self.ssl_handshake_ok()
        except ssl.SSLWantReadError:
            self.add_evt_read(self.fileno)
        except ssl.SSLWantWriteError:
            self.add_evt_write(self.fileno)
        except:
            self.delete_handler(self.fileno)
