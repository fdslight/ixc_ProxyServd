#!/usr/bin/env python3

import pywind as tcp_handler
import pywind.web.lib.websocket as websocket
import pywind.web.lib.httputils as httputils
import socket, time

class ws_listener(tcp_handler.tcp_handler):
    def init_func(self, creator, listen, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(listen)

        return self.fileno

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.ws_accept(cs,caddr)
        ''''''

    def ws_accept(self,cs,caddr):
        """重写这个方法
        :param cs:客户端套接字对象
        :param caddr:客户端地址
        :return:
        """
        pass

    def tcp_delete(self):
        self.ws_release()
        self.unregister(self.fileno)
        self.close()

    def ws_release(self):
        """重写这个方法
        :return:
        """

class ws_handler(tcp_handler.tcp_handler):
    __conn_timeout = 60
    __caddr = None

    __encoder = None
    __decoder = None

    __is_handshake = None

    __LOOP_TIMEOUT = 20
    __update_time = 0

    # 自定义的握手响应头
    __ext_handshake_resp_headers = None

    __is_close = False

    __is_sent_ping = False

    def init_func(self, creator, cs, caddr):
        self.__caddr = caddr

        self.__decoder = websocket.decoder(server_side=True)
        self.__encoder = websocket.encoder(server_side=True)

        self.__is_handshake = False
        self.__ext_handshake_resp_headers = []
        self.__is_close = False

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

        self.ws_init()

        return self.fileno

    def ws_init(self):
        """重写这个方法
        :return:
        """
        pass

    @property
    def caddr(self):
        return self.__caddr

    def response_error(self):
        resp_sts = httputils.build_http1x_resp_header("400 Bad Request", [("Sec-WebSocket-Version", 13), ],
                                                      version="1.1")

        self.writer.write(resp_sts.encode("iso-8859-1"))
        self.add_evt_write(self.fileno)

        self.delete_this_no_sent_data()

    def __do_handshake(self, byte_data):
        try:
            sts = byte_data.decode("iso-8859-1")
        except UnicodeDecodeError:
            self.response_error()
            return False

        try:
            rs = httputils.parse_htt1x_request_header(sts)
        except:
            self.response_error()
            return False

        req, headers = rs

        dic = {}
        for k, v in headers:
            k = k.lower()
            dic[k] = v

        if "sec-websocket-key" not in dic: return False
        ws_version = dic.get("sec-websocket-version", 0)

        is_err = False
        try:
            ws_version = int(ws_version)
            if ws_version != 13: is_err = True
        except ValueError:
            is_err = True
        if is_err:
            self.response_error()
            return False

        if not self.on_handshake(req, headers):
            self.response_error()
            return False

        sec_ws_key = dic["sec-websocket-key"]
        resp_sec_key = websocket.gen_handshake_key(sec_ws_key)

        resp_headers = [("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Accept", resp_sec_key)]

        resp_headers += self.__ext_handshake_resp_headers

        resp_sts = httputils.build_http1x_resp_header("101 Switching Protocols", resp_headers, version="1.1")

        self.writer.write(resp_sts.encode("iso-8859-1"))
        self.add_evt_write(self.fileno)

        return True

    def __handle_ping(self, message):
        self.__send_pong(message)

    def __handle_pong(self):
        self.__is_sent_ping = False
        self.__update_time = time.time()

    def __handle_close(self):
        if not self.__is_close:
            self.ws_close()
            return

        self.delete_handler(self.fileno)

    def __send_ping(self):
        wrap_msg = self.__encoder.build_ping()

        self.__is_sent_ping = True
        self.__update_time = time.time()
        self.writer.write(wrap_msg)
        self.add_evt_write(self.fileno)

    def __send_pong(self, message):
        wrap_msg = self.__encoder.build_pong(message)

        self.__update_time = time.time()

        self.writer.write(self.fileno)
        self.add_evt_write(wrap_msg)

    def on_handshake(self, request, headers):
        """重写这个方法
        :param request: 
        :param headers: 
        :return Boolean: False表示握手不允许,True表示握手允许 
        """
        return True

    def set_handshake_resp_header(self, name, value):
        """设置额外的响应头
        :param name: 
        :param value: 
        :return: 
        """
        self.__ext_handshake_resp_headers.append((name, value,))

    def set_ws_timeout(self, timeout):
        self.__conn_timeout = int(timeout)
        if self.__conn_timeout < 1: raise ValueError("wrong timeout value")

    def tcp_readable(self):
        rdata = self.reader.read()

        if not self.__is_handshake:
            if not self.__do_handshake(rdata): return
            self.__is_handshake = True
            return

        self.__decoder.input(rdata)

        while self.__decoder.continue_parse():
            self.__decoder.parse()
            if not self.__decoder.can_read_data(): continue
            data = self.__decoder.get_data()
            self.__handle_readable(data, self.__decoder.fin, self.__decoder.rsv, self.__decoder.opcode,
                self.__decoder.frame_ok())
            if self.__decoder.frame_ok(): self.__decoder.reset()
        self.__update_time = time.time()

        return

    def __handle_readable(self, message, fin, rsv, opcode, frame_finish):
        """
        :param message: 
        :param fin: 
        :param rsv: 
        :param opcode: 
        :param frame_finish: 
        :return: 
        """
        if opcode == websocket.OP_CLOSE:
            self.__handle_close()
            return

        if opcode == websocket.OP_PING:
            self.__handle_ping(message)
            return

        if opcode == websocket.OP_PONG:
            self.__handle_pong()
            return

        if not message: return

        if message: self.ws_readable(message, fin, rsv, opcode, frame_finish)

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.ws_release()
        self.unregister(self.fileno)
        self.close()

    def tcp_timeout(self):
        if not self.__is_handshake:
            self.delete_handler(self.fileno)
            return

        t = time.time()

        if t - self.__update_time >= self.__conn_timeout:
            if self.__is_close or self.__is_sent_ping:
                self.delete_handler(self.fileno)
                return
            self.__send_ping()
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def sendmsg(self, msg, fin, rsv, opcode):
        """发送websocket消息
        :param msg: 
        :return:
        """
        if opcode in (0x8, 0x9, 0xa,): raise ValueError("ping,pong,close frame cannot be sent by this function")
        if self.__is_close: raise ValueError("the connection is closed,you should not send data")

        self.__update_time = time.time()

        wrap_msg = self.__encoder.build_frame(msg, fin, rsv, opcode)

        self.add_evt_write(self.fileno)
        self.writer.write(wrap_msg)

    def ws_readable(self, message, fin, rsv, opcode, frame_finish):
        """重写这个方法
        :param message: 
        :param fin: 
        :param rsv: 
        :param opcode:
        :param is_finish: 
        :return: 
        """
        pass

    def ws_close(self, code=None):
        """关闭ws连接
        :return: 
        """
        if not code:
            code = ""
        else:
            code = str(code)

        wrap_msg = self.__encoder.build_close(code.encode("iso-8859-1"))

        self.__is_close = True
        self.add_evt_write(self.fileno)
        self.writer.write(wrap_msg)

        self.__update_time = time.time()
        self.delete_this_no_sent_data()


    def ws_release(self):
        """重写这个方法
        :return:
        """
        pass