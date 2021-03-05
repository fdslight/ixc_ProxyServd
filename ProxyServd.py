#!/usr/bin/env python3

import sys, os, json, getopt, socket, signal, time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import libProxyServd.proc as proc
import libProxyServd.handlers.proxyd as proxy
import libProxyServd.session as session

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

    __auth = None

    def init_func(self, debug=True):
        self.__debug = debug
        self.__sessions = {}
        self.__auth = session.auth_base()

        self.create_poll()

    def session_create(self, user_id: bytes, fd: int):
        if user_id in self.__sessions: return False

        context = session.context(user_id, fd)
        self.__sessions[user_id] = context

        return True

    def session_exists(self, user_id: bytes):
        """检查会话是否存在
        :param user_id:
        :return:
        """
        return user_id in self.__sessions

    def session_modify_fd(self, user_id: bytes, fd: int):
        """修改user_id地址到fd映射
        :param user_id:
        :param fd:
        :return:
        """
        if not self.session_exists(user_id): return False
        context = self.__sessions[user_id]
        context.set_fd(fd)
        return True

    def session_delete(self, user_id: bytes):
        if not self.session_exists(user_id): return

        del self.__sessions[user_id]

    def send_msg(self, user_id: bytes, msg: bytes):
        context = self.__sessions[user_id]
        fd = context.fileno
        context.msg_queue_append(msg)
        if fd < 0: return
        new_msg = context.msg_queue_pop()
        self.get_handler(context.fileno).send_msg(new_msg)

    @property
    def auth(self):
        return self.__auth

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
