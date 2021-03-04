#!/usr/bin/env python3

import sys, os, json, getopt, socket, signal, time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import libProxyServd.proc as proc
import libProxyServd.handlers.proxyd as proxy

PID_PATH = "/tmp/ixc_ProxyServd.pid"


def stop():
    pid = proc.get_pid(PID_PATH)
    if pid < 0: return
    os.remove(PID_PATH)
    os.kill(pid, signal.SIGINT)


class proxyd(dispatcher.dispatcher):
    __debug = None
    # sessions的结构如下
    __sessions = None

    def init_func(self, debug=True):
        self.__debug = debug
        self.__sessions = {}

    def msg_queue_append(self, user_id: bytes, byte_data: bytes):
        """向消息队列添加内容
        :param user_id:
        :param byte_data:
        :return:
        """
        if user_id not in self.__sessions: return False

        context = self.__sessions[user_id]

    def msg_queue_pop(self, user_id: bytes):
        pass

    def myloop(self):
        pass

    def release(self):
        pass


def main():
    help_doc = """
    debug | start | stop
    """

    if len(sys.argv) < 2:
        print(help_doc)
        return

    action = sys.argv[1]

    if action not in ("debug", "stop", "start",):
        print(help_doc)
        return

    if action == "stop":
        stop()
        return

    debug = True
    if action == "start":
        debug = False
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)

        pid = os.fork()
        if pid != 0: sys.exit(0)
        proc.write_pid(PID_PATH)

    cls = proxyd()
    try:
        cls.ioloop(debug=debug)
    except KeyboardInterrupt:
        cls.release()


if __name__ == '__main__': main()
