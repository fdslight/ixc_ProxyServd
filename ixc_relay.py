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
import ixc_proxy.lib.address_file as address_file


class service(dispatcher.dispatcher):
    __listen_fd = None
    # 当前流量大小
    __cur_traffic_size = None
    __limit_traffic_size = None
    __fpath = None
    __up_time = None
    __begin_time = None

    __limit_source_address = None

    # 最大TCP连接数量
    __max_tcp_conns = 0
    # 当前tcp连接数量
    __cur_tcp_conns = 0

    def init_func(self, bind, redirect, is_udp=False, is_ipv6=False, force_ipv6=False, limit_month_traffic=0,
                  nofork=False, udp_heartbeat_address=None, tcp_redirect_slave=None, limit_source_address=None,
                  max_tcp_conns=0
                  ):
        self.__cur_traffic_size = 0
        self.__up_time = time.time()
        self.__begin_time = 0
        self.__limit_source_address = limit_source_address
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
        self.__max_tcp_conns = max_tcp_conns
        self.__cur_tcp_conns = 0

        if not is_udp:
            logging.print_info("TCP connection limit %s" % max_tcp_conns)

        self.create_poll()

        if is_udp:
            handler = relay.udp_listener
        else:
            handler = relay.tcp_listener

        self.__listen_fd = self.create_handler(-1, handler, bind, redirect, listen_is_ipv6=is_ipv6,
                                               redirect_is_ipv6=force_ipv6, udp_heartbeat_address=udp_heartbeat_address,
                                               tcp_redirect_slave=tcp_redirect_slave)

    @property
    def limit_source_address(self):
        return self.__limit_source_address

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

    def is_permit_tcp_conn(self):
        """是否允许tcp连接"""
        if self.__max_tcp_conns <= 0: return True
        if self.__max_tcp_conns == self.__cur_tcp_conns:
            logging.print_info("cannot accept connection,cur conns is %s,max conns is %s" % (self.__cur_tcp_conns,
                                                                                             self.__max_tcp_conns))
            return False
        return True

    def tcp_conn_inc(self):
        """TCP连接数增加
        """
        self.__cur_tcp_conns += 1
        logging.print_info("the number of current tcp connection is %s" % self.__cur_tcp_conns)

    def tcp_conn_dec(self):
        """TCP连接数减少"""
        if self.__cur_tcp_conns <= 0: return
        self.__cur_tcp_conns -= 1
        logging.print_info("the number of current tcp connection is %s" % self.__cur_tcp_conns)

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
    --bind=address,port --redirect=host,port -p tcp | udp [--tcp-redirect-slave=host,port][-6] [--nofork]  
    [--limit-month-traffic=XXX][--udp-heartbeat-file=FILE]
    [--limit-source-address-file=FILE]
    [--max-tcp-conns=conn_num]
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "6p:",
                                   [
                                       "nofork", "bind=", "redirect=", "help", "limit-month-traffic=",
                                       "udp-heartbeat-file=", "tcp-redirect-slave=", "limit-source-address-file=",
                                       "max-tcp-conns="
                                   ])
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
    # TCP redirect从节点,用于切换,只支持TCP协议
    tcp_redirect_slave_s = None
    tcp_redirect_slave = None

    limit_source_address_file = None

    max_tcp_conns = 0

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
        if k == "--tcp-redirect-slave": tcp_redirect_slave_s = v
        if k == "--limit-source-address-file": limit_source_address_file = v
        if k == "--max-tcp-conns": max_tcp_conns = v

    try:
        max_tcp_conns = int(max_tcp_conns)
    except ValueError:
        print("ERROR:wrong max tcp conns value %s" % max_tcp_conns)
        return

    if max_tcp_conns < 0 or max_tcp_conns > 65535:
        print("ERROR:wrong max tcp conns value %s" % max_tcp_conns)
        return

    if limit_source_address_file is not None:
        if not os.path.isfile(limit_source_address_file):
            print("ERROR:not found limit source address file %s" % limit_source_address_file)
            return
        is_ok, limit_source_address = address_file.parse_address_list_from_file(limit_source_address_file)
        if not is_ok:
            print("ERROR:wrong source address ")
            for s in limit_source_address: print(s)
            return
        ''''''
    else:
        limit_source_address = []

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

    if bind[1] > 0xffff - 1 or bind[1] < 0:
        print("wrong bind port number")
        return

    if not cfg_check.is_ipv6(bind[0]) and (not cfg_check.is_ipv4(bind[0])):
        print("please set bind address")
        return

    if cfg_check.is_ipv6(bind[0]): is_ipv6 = True

    udp_heartbeat_address = []

    if protocol == "udp" and tcp_redirect_slave_s:
        print("error,udp protocol not support tcp-redirect-slave")
        return

    if protocol == "udp" and max_tcp_conns > 0:
        print("WARNING:udp not have argument max_tcp_conns")

    if protocol == "udp" and udp_heartbeat_file:
        if not os.path.isfile(udp_heartbeat_file):
            print("error,not found udp heartbeat file %s" % udp_heartbeat_file)
            return
        is_ok, address_list = address_file.parse_udp_heartbeat_address_from_file(udp_heartbeat_file, is_ipv6=is_ipv6)
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

    if tcp_redirect_slave_s:
        seq = tcp_redirect_slave_s.split(",")
        if len(seq) != 2:
            print("wrong tcp-redirect-slave address format")
            return
        try:
            tcp_redirect_slave = (seq[0], int(seq[1]),)
        except ValueError:
            print("wrong redirect address format")
            return
        ''''''
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
        instance.ioloop(bind, redirect, is_udp=is_udp, is_ipv6=is_ipv6, force_ipv6=force_ipv6,
                        limit_month_traffic=limit_month_traffic,
                        nofork=nofork, udp_heartbeat_address=udp_heartbeat_address,
                        tcp_redirect_slave=tcp_redirect_slave, limit_source_address=limit_source_address,
                        max_tcp_conns=max_tcp_conns)
    except KeyboardInterrupt:
        instance.release()
    except:
        logging.print_error()


if __name__ == '__main__': main()
