#!/usr/bin/env python3


import sys, getopt, os, signal, importlib, json, socket, struct

try:
    import dns.message
except ImportError:
    print("please install dnspython3 module")
    sys.exit(-1)

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
import ixc_proxy.lib.dns_utils as dns_utils
import ixc_proxy.lib.file_parser as rule_parser
import ixc_proxy.lib.host_match as host_match


class proxyd(dispatcher.dispatcher):
    __configs = None
    __debug = None

    __access = None
    __udp6_fileno = -1
    __tcp6_fileno = -1

    __udp_fileno = -1
    __tcp_fileno = -1
    __dns_fileno = -1
    __dns6_fileno = -1

    __tcp_crypto = None
    __udp_crypto = None

    __crypto_configs = None
    __tundev_fileno = -1

    __DEVNAME = "ixcsys"

    __enable_nat6 = False

    __dns_is_ipv6 = None
    __dns_addr = None
    __dns6_addr = None

    __host_match = None

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
        # if is_udplite:
        #    return
        print("A")
        if not self.__access.session_exists(_id): return
        print("B")
        fd = self.__access.udp_get(_id, (src_addr, sport,))
        if fd > 0:
            self.get_handler(fd).send_msg(byte_data, (dst_addr, dport,))
            return
        fd = self.create_handler(-1, udp_client.client, _id, (src_addr, sport,), is_ipv6=is_ipv6, is_udplite=is_udplite)
        if fd < 0:
            logging.print_error("cannot create udp client")
            return
        print("C")
        self.__access.udp_add(_id, (src_addr, sport,), fd)
        self.get_handler(fd).send_msg(byte_data, (dst_addr, dport))

    def load_dns_rules(self):
        path = "%s/ixc_configs/dns_rules.txt" % BASE_DIR

        self.__host_match.clear()

        if not os.path.isfile(path):
            logging.print_error("not found file %s" % path)
            return

        rules = rule_parser.parse_host_file(path)
        new_rules = []
        for host, _flags in rules:
            try:
                flags = int(_flags)
            except ValueError:
                logging.print_error("warning:wrong flags value for dns rule %s:%s" % (host, _flags))
                continue

            if flags not in (0, 1,):
                logging.print_error("warning:wrong flags value for dns rule %s:%s" % (host, _flags))
                continue

            new_rules.append((host, flags,))

        for host, flags in new_rules:
            if self.__host_match.exists(host):
                logging.print_error("warning:conflict rule for dns %s" % host)
                return
            self.__host_match.add_rule((host, flags,))
        return

    def init_func(self, debug, configs):
        self.create_poll()

        self.__configs = configs
        self.__debug = debug
        # 注意顺序,host_match要先实例化,才能加载DNS规则
        self.__host_match = host_match.host_match()
        self.load_dns_rules()

        self.__proxy = proxy.proxy(self.netpkt_sent_cb, self.udp_recv_cb)

        signal.signal(signal.SIGINT, self.__exit)
        signal.signal(signal.SIGUSR1, self.__handle_change_signal)

        conn_config = self.__configs["listen"]
        mod_name = "ixc_proxy.access.%s" % conn_config["access_module"]

        try:
            access = importlib.import_module(mod_name)
        except ImportError:
            print("cannot found access module")
            sys.exit(-1)

        crypto_mod_name = conn_config["crypto_module"]

        over_http = bool(int(conn_config["tunnel_over_http"]))

        # 当使用http模块时,禁用加密模块,直接使用https加密
        if over_http:
            tcp_crypto = "ixc_proxy.lib.crypto.noany.noany_tcp"
        else:
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

        if self.__ip4_mtu < 576 or self.__ip4_mtu > 1500:
            print("ERROR:Wrong IPv4 MTU value %s" % self.__ip4_mtu)
            return

        if self.__ip6_mtu < 576 or self.__ip6_mtu > 1500:
            print("ERROR:Wrong IPv6 MTU value %s" % self.__ip4_mtu)
            return

        ip_tcp_mss = nat_config.get("ip_tcp_mss", "0")
        ip6_tcp_mss = nat_config.get("ip6_tcp_mss", "0")

        try:
            ip_tcp_mss = int(ip_tcp_mss)
        except ValueError:
            print("ERROR:wrong ip tcp mss value %s" % ip_tcp_mss)
            return

        try:
            ip6_tcp_mss = int(ip6_tcp_mss)
        except ValueError:
            print("ERROR:wrong ip tcp mss value %s" % ip6_tcp_mss)
            return

        if ip_tcp_mss != 0:
            if ip_tcp_mss < 536 or ip_tcp_mss > 1460:
                print("ERROR:wrong ip tcp mss value %s,range is 536 to 1460 or 0" % ip_tcp_mss)
                return
            ''''''
        if ip6_tcp_mss != 0:
            if ip6_tcp_mss < 516 or ip6_tcp_mss > 1440:
                print("ERROR:wrong ip tcp mss value %s,range is 516 to 1440 or 0" % ip6_tcp_mss)
                return
            ''''''
        self.proxy.mtu_set(self.__ip4_mtu, False)
        self.proxy.mtu_set(self.__ip6_mtu, True)

        self.proxy.tcp_mss_set(ip_tcp_mss, False)
        self.proxy.tcp_mss_set(ip6_tcp_mss, True)

        dns_addr = nat_config["dns"]
        dnsv6_addr = nat_config.get("dns6", "::")

        if not netutils.is_ipv6_address(dnsv6_addr):
            print("ERROR:wrong dns6 address format")
            return

        if netutils.is_ipv6_address(dns_addr):
            is_ipv6 = True
        else:
            is_ipv6 = False

        self.__dns_is_ipv6 = is_ipv6
        self.__dns_addr = dns_addr
        self.__dns6_addr = dnsv6_addr

        self.__dns_fileno = self.create_handler(-1, dns_proxy.dns_client, dns_addr, is_ipv6=is_ipv6)

        if dnsv6_addr != "::":
            self.__dns6_fileno = self.create_handler(-1, dns_proxy.dns_client, dnsv6_addr, is_ipv6=True)

        enable_ipv6 = bool(int(nat_config["enable_nat66"]))
        subnet, prefix = netutils.parse_ip_with_prefix(nat_config["virtual_ip6_subnet"])
        eth_name = nat_config["eth_name"]

        if enable_ipv6:
            self.__config_gateway6(subnet, prefix, eth_name)
            self.proxy.ipalloc_subnet_set(subnet, prefix, True)

        subnet, prefix = netutils.parse_ip_with_prefix(nat_config["virtual_ip_subnet"])
        self.__config_gateway(subnet, prefix, eth_name)

        self.proxy.ipalloc_subnet_set(subnet, prefix, False)

        if not debug:
            sys.stdout = open(LOG_FILE, "a+")
            sys.stderr = open(ERR_FILE, "a+")

            self.proxy.clog_set("/tmp/ixc_proxy_stdout.log", "/tmp/ixc_proxy_stderr.log")

    def myloop(self):
        self.__access.access_loop()
        io_wait = self.proxy.loop()
        if not io_wait:
            self.set_default_io_wait_time(0)
        else:
            self.set_default_io_wait_time(5)

    @property
    def proxy(self):
        return self.__proxy

    def read_os_default_v6_router(self):
        """获取操作系统默认IPv6路由
        """
        f = os.popen("ip -6 route | grep default | awk -F ' ' '{print $3}'")
        router_address = f.read()
        router_address = router_address.replace("\n", "")
        router_address = router_address.replace("\r", "")
        f.close()
        if not router_address: return None

        return router_address

    def send_dns_err_msg_to_tunnel(self, _id: bytes, dns_xid: int, host: str, is_ipv6=False):
        drop_msg = dns_utils.build_dns_no_such_af_response(dns_xid, host, is_ipv6=is_ipv6)
        self.send_msg_to_tunnel(_id, proto_utils.ACT_DNS, drop_msg)

    def is_permitted_dns_request(self, _id: bytes, message: bytes):
        size = len(message)
        if size < 16: return False

        is_aaaa = dns_utils.is_aaaa_request(message)
        is_a = dns_utils.is_a_request(message)

        if not is_aaaa and not is_a: return True

        try:
            msg = dns.message.from_wire(message)
        except:
            return False

        dns_xid, = struct.unpack("!H", message[0:2])

        questions = msg.question
        q = questions[0]

        host = b".".join(q.name[0:-1]).decode("iso-8859-1")

        is_matched, flags = self.__host_match.match(host)
        if not is_matched: return True

        if flags == 0 and is_a:
            self.send_dns_err_msg_to_tunnel(_id, dns_xid, host, is_ipv6=False)
            return False

        if flags == 1 and is_aaaa:
            self.send_dns_err_msg_to_tunnel(_id, dns_xid, host, is_ipv6=True)
            return False

        return True

    def send_msg_to_tunnel(self, _id: bytes, action: int, message: bytes):
        if not self.__access.session_exists(_id): return
        # 此处找打用户的文件描述符以及IP地址
        fileno, username, address, udp_sessions, priv_data = self.__access.get_session_info(_id)

        if not self.handler_exists(fileno): return

        # 此处检查是否是TCP,如果是TCP那么检查session id是否一致
        if self.get_handler(fileno).is_tcp():
            session_id = self.get_handler(fileno).session_id
            if not session_id: return
            if session_id != _id: return
        if not self.__access.data_for_send(_id, len(message)): return
        if not self.get_handler(fileno).is_tunnel_handler(): return
        self.get_handler(fileno).send_msg(_id, address, action, message)

    def handle_msg_from_tunnel(self, fileno, session_id, address, action, message):
        # 此处验证用户
        auth_ok = self.__access.data_from_recv(fileno, session_id, address, len(message))
        if not auth_ok: return

        self.__access.modify_session(session_id, fileno, address)

        if action == proto_utils.ACT_DNS:
            # 检查是否允许DNS请求
            if not self.is_permitted_dns_request(session_id, message): return
            # 如果有填写DNSv6服务器那么转发AAAA流量到DNSv6服务器
            if self.__dns6_fileno > 0 and dns_utils.is_aaaa_request(message):
                self.get_handler(self.__dns6_fileno).send_msg(session_id, message)
            else:
                self.get_handler(self.__dns_fileno).send_msg(session_id, message)
            return
        if action == proto_utils.ACT_IPDATA:
            self.proxy.netpkt_handle(session_id, message, proxy.FROM_LAN)
            return

    def handle_ippkt_from_tundev(self, msg: bytes):
        self.proxy.netpkt_handle(bytes(16), msg, proxy.FROM_WAN)

    def handle_dns_msg_from_server(self, _id: bytes, message: bytes):
        self.send_msg_to_tunnel(_id, proto_utils.ACT_DNS, message)

    def send_udp_msg_to_tunnel(self, user_id: bytes, saddr: tuple, daddr: tuple, message: bytes, is_ipv6=False,
                               is_udplite=False):
        if not self.__access.session_exists(user_id): return
        if is_ipv6:
            byte_saddr = socket.inet_pton(socket.AF_INET6, saddr[0])
            byte_daddr = socket.inet_pton(socket.AF_INET6, daddr[0])
        else:
            byte_saddr = socket.inet_pton(socket.AF_INET, saddr[0])
            byte_daddr = socket.inet_pton(socket.AF_INET, daddr[0])
        if is_udplite:
            csum_coverage = 8
        else:
            csum_coverage = 0
        self.proxy.udp_send(byte_saddr, byte_daddr, saddr[1], daddr[1], False, is_ipv6, csum_coverage, message)

    def udp_del(self, user_id: bytes, address: tuple):
        if not self.__access.session_exists(user_id): return
        self.__access.udp_del(user_id, address)

    def tell_unregister_session(self, user_id: bytes, fileno: int, udp_conns: dict):
        # 此处需要检测fd被重用的情况
        if self.handler_exists(fileno):
            if self.get_handler(fileno).is_tcp():
                session_id = self.get_handler(fileno).session_id
                if session_id:
                    if session_id == user_id: self.delete_handler(fileno)
                ''''''
            ''''''
        tmplist = []
        for _id in udp_conns:
            fd = udp_conns[_id]
            tmplist.append(fd)

        for fd in tmplist:
            self.delete_handler(fd)

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

    def __config_gateway6(self, subnet, prefix, eth_name):
        router_address = self.read_os_default_v6_router()

        os.system("ip -6 route add %s/%s dev %s" % (subnet, prefix, self.__DEVNAME))
        os.system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding")
        os.system("ip6tables -t nat -I POSTROUTING -s %s/%s  -j MASQUERADE" % (subnet, prefix,))
        os.system("ip6tables -A FORWARD -s %s/%s -j ACCEPT" % (subnet, prefix))

        # 检查IPv6网关是否存在,修改机器网络参数后,IPv6默认网关可能消失
        router_address2 = self.read_os_default_v6_router()
        if not router_address2:
            if router_address: os.system("ip -6 route add default via %s dev %s" % (router_address, eth_name,))

    def __exit(self, signum, frame):
        if self.handler_exists(self.__dns6_fileno):
            self.delete_handler(self.__dns6_fileno)
        if self.handler_exists(self.__dns_fileno):
            self.delete_handler(self.__dns_fileno)
        if self.handler_exists(self.__tcp6_fileno):
            self.delete_handler(self.__tcp6_fileno)
        if self.handler_exists(self.__tcp_fileno):
            self.delete_handler(self.__tcp_fileno)

        sys.exit(0)

    def __handle_change_signal(self, signum, frame):
        self.load_dns_rules()
        self.__access.handle_user_change_signal()


def __start_service(debug):
    if not os.path.isfile("/usr/sbin/iptables"):
        print("ERROR:please install iptables")
        return
    if not os.path.isfile("/usr/sbin/ip6tables"):
        print("ERROR:please install ip6tables")
        return

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
