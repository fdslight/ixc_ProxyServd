#!/usr/bin/env python3

import sys, os, json, getopt, socket, signal, time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import libProxyServd.proc as proc
import libProxyServd.handlers.proxyd as proxy

PID_PATH = "/tmp/ixc_ProxyServd.pid"


class proxyd(object):
    def __init__(self, debug=False):
        self.__debug = debug

    def load_configs(self):
        pass

    def release(self):
        pass


def stop():
    pid = proc.get_pid(PID_PATH)
    if pid < 0: return
    os.remove(PID_PATH)
    os.kill(pid, signal.SIGINT)


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

    try:
        opts, args = getopt.getopt(sys.argv[2:], "", ["port=", "bind_ip="])
    except getopt.GetoptError:
        print(help_doc)
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

    cls = proxyd(debug=debug)
    try:
        cls.monitor()
    except KeyboardInterrupt:
        cls.release()


if __name__ == '__main__': main()
