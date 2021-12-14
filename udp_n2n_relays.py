#!/usr/bin/env python3
import sys, getopt, os, signal, importlib, json, socket

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_FILE = "/tmp/udp_n2n_relays.pid"
LOG_FILE = "/tmp/udp_n2n_relays.log"
ERR_FILE = "/tmp/udp_n2n_s_error.log"

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as configfile
import pywind.lib.netutils as netutils
import ixc_proxy.lib.proc as proc
import ixc_proxy.handlers.n2n_server as n2n_server

import ixc_proxy.lib.logging as logging


class server(dispatcher.dispatcher):
    __configs = None
    __debug = None

    # 客户端到NAT服务端的映射
    __fwd_tb = None
    # NAT服务端到客户端的映射
    __fwd_tb_reverse = None

    def init_func(self, debug):
        if not debug:
            sys.stdout = open(LOG_FILE, "w")
            sys.stderr = open(ERR_FILE, "w")

        self.__debug = debug
        self.__fwd_tb = {}
        self.__fwd_tb_reverse = {}

        self.__configs = configfile.ini_parse_from_file("%s/fdslight_etc/udp_n2n_server.ini" % BASE_DIR)
        self.create_poll()
        self.create()

    def create(self):
        for k, v in self.__configs.items():
            listen_addr = v["listen_addr"]
            nat_after_server_port = int(v["nat_after_server_port"])
            forward_port = int(v["forward_port"])

            if netutils.is_ipv6_address(listen_addr):
                is_ipv6 = True
            else:
                is_ipv6 = False

            nat_server_fd = self.create_handler(-1, n2n_server.n2n_wrapper, (listen_addr, nat_after_server_port,),
                                                is_ipv6=is_ipv6)
            forward_fd = self.create_handler(-1, n2n_server.n2n_raw, (listen_addr, forward_port,), is_ipv6=is_ipv6)

            self.__fwd_tb[forward_fd] = nat_server_fd
            self.__fwd_tb_reverse[nat_server_fd] = forward_fd

    def send_to_raw_client(self, from_fd, message):
        if from_fd not in self.__fwd_tb_reverse: return
        dst_fd = self.__fwd_tb_reverse[from_fd]
        self.send_message_to_handler(from_fd, dst_fd, message)

    def send_to_wrapper_client(self, from_fd, message):
        if from_fd not in self.__fwd_tb: return
        dst_fd = self.__fwd_tb[from_fd]

        self.send_message_to_handler(from_fd, dst_fd, message)

    def myloop(self):
        pass

    def release(self):
        for fd1, fd2 in self.__fwd_tb.items():
            self.delete_handler(fd1)
            self.delete_handler(fd2)


def __start_service(debug):
    if not debug and os.path.isfile(PID_FILE):
        print("the udp_n2n_relay server process exists")
        return

    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

    cls = server()

    if debug:
        cls.ioloop(debug)
        return
    try:
        cls.ioloop(debug)
    except:
        logging.print_error()
        cls.release()

    os.remove(PID_FILE)
    sys.exit(0)


def __stop_service():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found udp_n2n_relay server process")
        return

    os.kill(pid, signal.SIGINT)


def __update_user_configs():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found udp_n2n_relay process")
        return

    os.kill(pid, signal.SIGUSR1)


def main():
    help_doc = """
    debug | start | stop    debug,start or stop application
    """

    if len(sys.argv) != 2:
        print(help_doc)
        return

    d = sys.argv[1]

    if not d:
        print(help_doc)
        return

    if d not in ("debug", "start", "stop"):
        print(help_doc)
        return

    debug = False

    if d == "stop":
        __stop_service()
        return

    if d == "debug": debug = True
    if d == "start": debug = False

    __start_service(debug)


if __name__ == '__main__': main()
