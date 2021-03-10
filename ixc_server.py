#!/usr/bin/env python3
import sys, getopt, os, signal, importlib, json, socket

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_FILE = "/tmp/ixc_proxy.pid"
LOG_FILE = "/tmp/ixc_proxy.log"
ERR_FILE = "/tmp/ixc_proxy_error.log"

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as configfile
import pywind.lib.netutils as netutils

import ixc_proxy.handlers.dns_proxy as dns_proxy
import ixc_proxy.handlers.tundev as tundev
import ixc_proxy.handlers.tunnels as tunnels
import ixc_proxy.handlers.udp_client as udp_client
import ixc_proxy.lib.proxy as proxy
import ixc_proxy.lib.logging as logging
import ixc_proxy.lib.proc as proc
import ixc_proxy.lib.base_proto.utils as proto_utils


class proxyd(dispatcher.dispatcher):
    __configs = None
    __debug = None

    __access = None
    __udp6_fileno = -1
    __tcp6_fileno = -1

    __udp_fileno = -1
    __tcp_fileno = -1
    __dns_fileno = -1

    __tcp_crypto = None
    __udp_crypto = None

    __crypto_configs = None
    __tundev_fileno = -1

    __DEVNAME = "ixcsys"

    __enable_nat6 = False

    __dns_is_ipv6 = None
    __dns_addr = None

    __proxy = None

    @property
    def http_configs(self):
        configs = self.__configs.get("tunnel_over_http", {})

        pyo = {"auth_id": configs.get("auth_id", "ixcsys"), "origin": configs.get("origin", "example.com")}

        return pyo

    def load_crypto_configs(self, crypto_fpath: str):
        if not os.path.isfile(crypto_fpath):
            raise SystemError("not found file %s", crypto_fpath)

        with open(crypto_fpath, "r") as f:
            s = f.read()
        f.close()
        return json.loads(s)

    def netpkt_sent_cb(self, byte_data: bytes, _id: bytes, _from: int):
        # 如果数据来源于LAN那么发送到TUN设备
        if _from == proxy.FROM_LAN:
            self.get_handler(self.__tundev_fileno).send_msg(byte_data)
            return
        self.send_msg_to_tunnel(_id, proto_utils.ACT_IPDATA, byte_data)

    def udp_recv_cb(self, _id: bytes, src_addr: str, dst_addr: str, sport: int, dport: int, is_udplite: bool,
                    is_ipv6: bool,
                    byte_data: bytes):
        # 禁用UDPLite支持
        if is_udplite:
            return
        if not self.__access.session_exists(_id): return
        fd = self.__access.udp_get(_id, (src_addr, sport,))
        if fd > 0:
            self.get_handler(fd).send_msg(byte_data, (dst_addr, dport,))
            return
        fd = self.create_handler(-1, udp_client.client, _id, (src_addr, sport,), is_ipv6=is_ipv6)
        if fd < 0:
            logging.print_error("cannot create udp client")
            return
        self.get_handler(fd).send_msg(byte_data, (dst_addr, dport))

    def init_func(self, debug, configs):
        self.create_poll()

        self.__configs = configs
        self.__debug = debug
        self.__proxy = proxy.proxy(self.netpkt_sent_cb, self.udp_recv_cb)

        signal.signal(signal.SIGINT, self.__exit)
        signal.signal(signal.SIGUSR1, self.__handle_user_change_signal)

        conn_config = self.__configs["listen"]
        mod_name = "ixc_proxy.access.%s" % conn_config["access_module"]

        try:
            access = importlib.import_module(mod_name)
        except ImportError:
            print("cannot found access module")
            sys.exit(-1)

        crypto_mod_name = conn_config["crypto_module"]

        tcp_crypto = "ixc_proxy.lib.crypto.%s.%s_tcp" % (crypto_mod_name, crypto_mod_name)
        udp_crypto = "ixc_proxy.lib.crypto.%s.%s_udp" % (crypto_mod_name, crypto_mod_name)

        crypto_configfile = "%s/ixc_configs/%s" % (BASE_DIR, conn_config["crypto_configfile"])
        try:
            self.__tcp_crypto = importlib.import_module(tcp_crypto)
            self.__udp_crypto = importlib.import_module(udp_crypto)
        except ImportError:
            print("cannot found tcp or udp crypto module")
            sys.exit(-1)

        if not os.path.isfile(crypto_configfile):
            print("cannot found crypto configfile")
            sys.exit(-1)

        try:
            self.__crypto_configs = self.load_crypto_configs(crypto_configfile)
        except:
            print("crypto configfile should be json file")
            sys.exit(-1)

        enable_ipv6 = bool(int(conn_config["enable_ipv6"]))

        listen_port = int(conn_config["listen_port"])

        conn_timeout = int(conn_config["conn_timeout"])

        listen_ip = conn_config["listen_ip"]
        listen_ip6 = conn_config["listen_ip6"]

        listen = (listen_ip, listen_port,)
        listen6 = (listen_ip6, listen_port)

        over_http = bool(int(conn_config["tunnel_over_http"]))

        if enable_ipv6:
            self.__tcp6_fileno = self.create_handler(-1, tunnels.tcp_tunnel, listen6, self.__tcp_crypto,
                                                     self.__crypto_configs, conn_timeout=conn_timeout, is_ipv6=True,
                                                     over_http=over_http)
            self.__udp6_fileno = self.create_handler(-1, tunnels.udp_tunnel, listen6, self.__udp_crypto,
                                                     self.__crypto_configs, is_ipv6=True)

        self.__tcp_fileno = self.create_handler(-1, tunnels.tcp_tunnel, listen, self.__tcp_crypto,
                                                self.__crypto_configs, conn_timeout=conn_timeout, is_ipv6=False,
                                                over_http=over_http)
        self.__udp_fileno = self.create_handler(-1, tunnels.udp_tunnel, listen, self.__udp_crypto,
                                                self.__crypto_configs, is_ipv6=False)

        self.__tundev_fileno = self.create_handler(-1, tundev.tundev, self.__DEVNAME)
        self.__access = access.access(self)

        nat_config = configs["nat"]

        try:
            self.__ip4_mtu = int(nat_config["mtu"])
        except KeyError:
            self.__ip4_mtu = 1400
        try:
            self.__ip6_mtu = int(nat_config["mtu_v6"])
        except KeyError:
            self.__ip6_mtu = 1280

        dns_addr = nat_config["dns"]
        if netutils.is_ipv6_address(dns_addr):
            is_ipv6 = True
        else:
            is_ipv6 = False

        self.__dns_is_ipv6 = is_ipv6
        self.__dns_addr = dns_addr

        self.__dns_fileno = self.create_handler(-1, dns_proxy.dns_client, dns_addr, is_ipv6=is_ipv6)

        enable_ipv6 = bool(int(nat_config["enable_nat66"]))
        subnet, prefix = netutils.parse_ip_with_prefix(nat_config["virtual_ip6_subnet"])
        eth_name = nat_config["eth_name"]

        if enable_ipv6: self.__config_gateway6(subnet, prefix, eth_name)

        subnet, prefix = netutils.parse_ip_with_prefix(nat_config["virtual_ip_subnet"])
        self.__config_gateway(subnet, prefix, eth_name)

        if not debug:
            sys.stdout = open(LOG_FILE, "a+")
            sys.stderr = open(ERR_FILE, "a+")

    def myloop(self):
        self.__access.access_loop()
        io_wait = self.proxy.loop()
        if not io_wait:
            self.set_default_io_wait_time(0)
        else:
            self.set_default_io_wait_time(10)

    @property
    def proxy(self):
        return self.__proxy

    def send_msg_to_tunnel(self, _id: bytes, action: int, message: bytes):
        if not self.__access.session_exists(_id): return
        # 此处找打用户的文件描述符以及IP地址
        fileno, username, address, udp_sessions, priv_data = self.__access.get_session_info()

        if not self.handler_exists(fileno): return

        # 此处检查是否是TCP,如果是TCP那么检查session id是否一致
        if self.get_handler(fileno).is_tcp():
            session_id = self.get_handler(fileno).session_id
            if not session_id: return
            if session_id != _id: return
        if not self.__access.data_for_send(_id, len(message)): return

        self.get_handler(fileno).send_msg(_id, address, action, message)

    def handle_msg_from_tunnel(self, fileno, session_id, address, action, message):
        # 此处验证用户
        auth_ok = self.__access.data_from_recv(fileno, session_id, address, len(message))
        if not auth_ok: return

        self.__access.modify_session(session_id, fileno, address)

        if action == proto_utils.ACT_DNS:
            self.get_handler(self.__dns_fileno).send_msg(session_id, message)
            return

        if action == proto_utils.ACT_IPDATA:
            print("zzzz")
            self.proxy.netpkt_handle(session_id, message, proxy.FROM_LAN)
            return

    def handle_ippkt_from_tundev(self, msg: bytes):
        self.proxy.netpkt_handle(bytes(16), msg, proxy.FROM_WAN)

    def handle_dns_msg_from_server(self, _id: bytes, message: bytes):
        self.send_msg_to_tunnel(_id, proto_utils.ACT_DNS, message)

    def send_udp_msg_to_tunnel(self, user_id: bytes, saddr: tuple, daddr: tuple, message: bytes, is_ipv6=False):
        if not self.__access.session_exists(user_id): return
        if is_ipv6:
            byte_saddr = socket.inet_pton(socket.AF_INET6, saddr[0])
            byte_daddr = socket.inet_pton(socket.AF_INET6, daddr[0])
        else:
            byte_saddr = socket.inet_pton(socket.AF_INET, saddr[0])
            byte_daddr = socket.inet_pton(socket.AF_INET, daddr[0])
        self.proxy.udp_send(byte_saddr, byte_daddr, saddr[1], daddr[1], False, is_ipv6, 0, message)

    def udp_del(self, user_id: bytes, address: tuple):
        if not self.__access.session_exists(user_id): return
        self.__access.udp_del(user_id, address)

    def __config_gateway(self, subnet, prefix, eth_name):
        """ 配置IPV4网关
        :param subnet:子网
        :param prefix:子网前缀
        :param eth_name:流量出口网卡名
        :return:
        """
        # 添加一条到tun设备的IPV4路由
        cmd = "ip route add %s/%s dev %s" % (subnet, prefix, self.__DEVNAME)
        os.system(cmd)
        # 开启ip forward
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        # 开启IPV4 NAT

        os.system("iptables -t nat -A POSTROUTING -s %s/%s -o %s -j MASQUERADE" % (subnet, prefix, eth_name,))
        os.system("iptables -A FORWARD -s %s/%s -j ACCEPT" % (subnet, prefix))

    def __config_gateway6(self, ip6_subnet, prefix, eth_name):
        """配置IPV6网关
        :param ip6address:
        :param eth_name:
        :return:
        """
        # 开启IPV6流量重定向
        os.system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding")

        # os.system("ip -6 route add default via %s dev %s" % (ip6_gw, eth_name,))

        # os.system("ip6tables -t nat -A POSTROUTING -s %s/%s -o %s -j MASQUERADE" % (ip6_subnet, prefix, eth_name,))
        # os.system("ip6tables -A FORWARD -s %s/%s -j ACCEPT" % (ip6_subnet, prefix))

    def __exit(self, signum, frame):
        if self.handler_exists(self.__dns_fileno):
            self.delete_handler(self.__dns_fileno)
        if self.handler_exists(self.__tcp6_fileno):
            self.delete_handler(self.__tcp6_fileno)
        if self.handler_exists(self.__tcp_fileno):
            self.delete_handler(self.__tcp_fileno)

        sys.exit(0)

    def __handle_user_change_signal(self, signum, frame):
        self.__access.handle_user_change_signal()


def __start_service(debug):
    if not debug and os.path.isfile(PID_FILE):
        print("the proxy server process exists")
        return

    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

    configs = configfile.ini_parse_from_file("%s/ixc_configs/config.ini" % BASE_DIR)
    cls = proxyd()

    if debug:
        cls.ioloop(debug, configs)
        return
    try:
        cls.ioloop(debug, configs)
    except:
        logging.print_error()

    os.remove(PID_FILE)
    sys.exit(0)


def __stop_service():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found proxy server process")
        return

    os.kill(pid, signal.SIGINT)


def __update_user_configs():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found proxy process")
        return

    os.kill(pid, signal.SIGUSR1)


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    -u      user_configs            update configs           
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:", [])
    except getopt.GetoptError:
        print(help_doc)
        return
    d = ""
    u = ""

    for k, v in opts:
        if k == "-d": d = v
        if k == "-u": u = v

    if not u and not d:
        print(help_doc)
        return

    if u and u != "user_configs":
        print(help_doc)
        return

    if u:
        __update_user_configs()
        return

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
