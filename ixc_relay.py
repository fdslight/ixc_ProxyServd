#!/usr/bin/env python3

import sys, os, getopt, json
import time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

import pywind.evtframework.evt_dispatcher as dispatcher
import ixc_proxy.handlers.relay as relay
import ixc_proxy.lib.cfg_check as cfg_check
import ixc_proxy.lib.logging as logging
import ixc_proxy.lib.udp_heartbeat_file as udp_heartbeat_file_utils


class service(dispatcher.dispatcher):
    __listen_fd = None
    # 当前流量大小
    __cur_traffic_size = None
    __limit_traffic_size = None
    __fpath = None
    __up_time = None
    __begin_time = None

    def init_func(self, bind, redirect, is_udp=False, is_ipv6=False, force_ipv6=False, limit_month_traffic=0,
                  nofork=False, udp_heartbeat_address=None):
        self.__cur_traffic_size = 0
        self.__up_time = time.time()
        self.__begin_time = 0
        # 限制的流量大小单位为GB
        self.__limit_traffic_size = limit_month_traffic * 1024 * 1024 * 1024
        if is_udp:
            s = "udp"
            self.__fpath = "%s_%s_relay_udp_traffic.json" % (bind[0], bind[1])
        else:
            s = "tcp"
            self.__fpath = "%s_%s_relay_tcp_traffic.json" % (bind[0], bind[1])

        if not nofork:
            sys.stdout = open("/tmp/ixc_relay_%s_%s_%s.log" % (s, bind[0], bind[1]), "w")
            sys.stderr = open("/tmp/ixc_relay_err_%s_%s_%s.log" % (s, bind[0], bind[1]), "w")

        self.load_traffic_statistics()

        self.__listen_fd = -1
        self.create_poll()

        if is_udp:
            handler = relay.udp_listener
        else:
            handler = relay.tcp_listener

        self.__listen_fd = self.create_handler(-1, handler, bind, redirect, listen_is_ipv6=is_ipv6,
                                               redirect_is_ipv6=force_ipv6, udp_heartbeat_address=udp_heartbeat_address)

    def traffic_statistics(self, traffic_size):
        self.__cur_traffic_size += traffic_size

    def have_traffic(self):
        """是否还有流量
        """
        if self.__limit_traffic_size <= 0: return True
        if self.__cur_traffic_size >= self.__limit_traffic_size: return False

        return True

    def load_traffic_statistics(self):
        if not os.path.isfile(self.__fpath):
            self.__begin_time = time.time()
            self.__cur_traffic_size = 0
            return

        with open(self.__fpath, "r") as f:
            s = f.read()
        f.close()

        dic = json.loads(s)
        self.__begin_time = int(dic["begin_time"])
        self.__cur_traffic_size = int(dic["traffic_size"])

    def reset_traffic(self):
        now = time.time()
        if now - self.__begin_time > 86400 * 30:
            self.__begin_time = now
            self.__cur_traffic_size = 0
            return

    def flush_traffic_statistics(self):
        t = time.localtime(self.__begin_time)
        s = json.dumps({"begin_time": self.__begin_time, "traffic_size": self.__cur_traffic_size,
                        "comment_used_traffic_size": "%sGB" % int(self.__cur_traffic_size / 1024 / 1024 / 1024),
                        "comment_traffic_limit": "%sGB" % int(self.__limit_traffic_size / 1024 / 1024 / 1024),
                        "comment_begin_time": "%s" % time.strftime("%Y-%m-%d %H:%M:%S", t)
                        })
        with open(self.__fpath, "w") as f:
            f.write(s)
        f.close()

    def myloop(self):
        now = time.time()
        # 每隔一段时间刷新流量统计到文件
        if now - self.__up_time > 180:
            self.flush_traffic_statistics()
            self.reset_traffic()
            self.__up_time = now
        ''''''

    def release(self):
        if self.__listen_fd > 0: self.delete_handler(self.__listen_fd)

        sys.stdout.flush()
        sys.stderr.flush()
        sys.stdout.close()
        sys.stderr.close()


def main():
    help_doc = """
    --bind=address,port --redirect=host,port -p tcp | udp [-6] [--nofork]  [--limit-month-traffic=XXX][--udp-heartbeat-file=FILE]
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "6p:",
                                   ["nofork", "bind=", "redirect=", "help", "limit-month-traffic=",
                                    "udp-heartbeat-file="])
    except getopt.GetoptError:
        print(help_doc)
        return

    if len(sys.argv) < 2:
        print(help_doc)
        return

    bind = None
    redirect = None
    force_ipv6 = False

    bind_s = None
    redirect_s = None
    fork = True
    is_ipv6 = False
    protocol = None
    limit_month_traffic = "0"
    # UDP心跳文件,如果存在此参数并且是UDP协议,那么服务端发送主动心跳
    udp_heartbeat_file = ""

    for k, v in opts:
        if k == "-6": force_ipv6 = True
        if k == "--bind": bind_s = v
        if k == "--redirect": redirect_s = v
        if k == "--help":
            print(help_doc)
            return
        if k == "--nofork": fork = False
        if k == "-p": protocol = v
        if k == "--limit-month-traffic": limit_month_traffic = v
        if k == "--udp-heartbeat-file": udp_heartbeat_file = v

    if not bind_s:
        print("please set bind address")
        return

    if not redirect_s:
        print("please set redirect address")
        return

    if not protocol:
        print("not set protocol")
        return

    if protocol not in ("tcp", "udp",):
        print("unsupport protocol %s" % protocol)
        return

    if protocol == "tcp" and udp_heartbeat_file:
        print("error,only UDP support udp-heartbeat-file")
        return

    try:
        limit_month_traffic = int(limit_month_traffic)
    except ValueError:
        print("wrong traffic value")
        return

    seq = bind_s.split(",")
    if len(seq) != 2:
        print("wrong bind address format")
        return

    try:
        bind = (seq[0], int(seq[1]),)
    except ValueError:
        print("wrong bind address format")
        return

    if bind[1] > 0xffff - 1 or bind[1] < 1:
        print("wrong bind port number")
        return

    if not cfg_check.is_ipv6(bind[0]) and (not cfg_check.is_ipv4(bind[0])):
        print("please set bind address")
        return

    if cfg_check.is_ipv6(bind[0]): is_ipv6 = True

    udp_heartbeat_address = []

    if protocol == "udp" and udp_heartbeat_file:
        if not os.path.isfile(udp_heartbeat_file):
            print("error,not found udp heartbeat file %s" % udp_heartbeat_file)
            return
        is_ok, address_list = udp_heartbeat_file_utils.parse_from_file(udp_heartbeat_file, is_ipv6=is_ipv6)
        if not is_ok:
            print("error IP address")
            for line in address_list:
                print(line)
            return
        udp_heartbeat_address = address_list

    seq = redirect_s.split(",")
    if len(seq) != 2:
        print("wrong redirect address format")
        return

    try:
        redirect = (seq[0], int(seq[1]),)
    except ValueError:
        print("wrong redirect address format")
        return

    if fork:
        pid = os.fork()
        if pid != 0: sys.exit(0)
        os.umask(0)
        os.setsid()
        pid = os.fork()
        if pid != 0: sys.exit(0)

    is_udp = False
    if protocol == "udp": is_udp = True
    if fork:
        nofork = False
    else:
        nofork = True

    instance = service()
    try:
        instance.ioloop(bind, redirect, is_udp=is_udp, force_ipv6=force_ipv6, limit_month_traffic=limit_month_traffic,
                        nofork=nofork, udp_heartbeat_address=udp_heartbeat_address)
    except KeyboardInterrupt:
        instance.release()
    except:
        logging.print_error()


if __name__ == '__main__': main()
