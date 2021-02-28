#!/usr/bin/env python3
import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.web.handlers.scgi as scgi


class appserver(dispatcher.dispatcher):
    __configs = None
    __fileno = None

    def __init__(self, configs):
        super(appserver, self).__init__()
        self.__configs = configs

    def run(self):
        self.create_poll()
        fd = self.create_handler(-1, scgi.scgid_listen, self.__configs)
        self.__fileno = fd
        self.get_handler(fd).after()

    def init_func(self):
        self.run()

    def release(self):
        """释放资源
        :return:
        """
        if self.__fileno > 0: self.delete_handler(self.__fileno)
