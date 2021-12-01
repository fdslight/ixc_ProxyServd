#!/usr/bin/env python3
import pywind.evtframework.handlers.handler as handler
import pywind.lib.reader as reader
import pywind.lib.writer as writer
import socket


class tcp_handler(handler.handler):
    __reader = None
    __writer = None
    __socket = None

    # 作为客户端连接是否成功
    __conn_ok = False
    # 作为客户端的连接事件标记,用以表示是否连接成功
    __conn_ev_flag = 0
    __is_async_socket_client = False
    __is_listen_socket = False
    __delete_this_no_sent_data = False
    __is_closed = None

    # 一次性循环读取次数
    tcp_loop_read_num = None
    # 读取缓冲区大小
    tcp_recv_buf_size = None

    def __init__(self):
        super(tcp_handler, self).__init__()
        self.__reader = reader.reader()
        self.__writer = writer.writer()
        self.__is_closed = False
        self.tcp_loop_read_num = 10
        self.tcp_recv_buf_size = 2048

    def init_func(self, creator_fd, *args, **kwargs):
        """
        :param creator_fd:
        :param args:
        :param kwargs:
        :return fileno:
        """
        pass

    def after(self, *args, **kwargs):
        """之后要做的事情,有用户自己的服务端程序调用,可能常常用于多进程
        """
        pass

    def set_socket(self, s):
        s.setblocking(0)
        self.set_fileno(s.fileno())
        self.__socket = s

    def accept(self):
        return self.socket.accept()

    def close(self):
        self.__is_closed = True
        self.socket.close()

    @property
    def socket(self):
        return self.__socket

    def bind(self, address):
        self.socket.bind(address)

    def listen(self, backlog):
        self.__is_listen_socket = True
        self.socket.listen(backlog)

    @property
    def reader(self):
        return self.__reader

    @property
    def writer(self):
        return self.__writer

    def send(self, *args):
        return self.socket.send(*args)

    def recv(self, *args):
        return self.socket.recv(*args)

    def evt_read(self):
        if self.__is_listen_socket:
            self.tcp_accept()
            return

        if self.__is_async_socket_client and not self.is_conn_ok():
            self.__conn_ev_flag = 1
            return

        # 使用for,防止一直读取数据
        for i in range(self.tcp_loop_read_num):
            try:
                recv_data = self.recv(self.tcp_recv_buf_size)
                if not recv_data:
                    # 处理未接收完毕的数据
                    if self.reader.size() > 0: self.tcp_readable()
                    if self.handler_exists(self.fileno): self.error()
                    break
                self.reader._putvalue(self.handle_tcp_received_data(recv_data))
            except BlockingIOError:
                self.tcp_readable()
                break
            except ConnectionResetError:
                self.error()
                break
            except ConnectionError:
                self.error()
                break
            except TimeoutError:
                self.error()
                break
            ''''''
        return

    def evt_write(self):
        if self.__is_closed: return
        if self.__is_async_socket_client and not self.is_conn_ok():
            self.unregister(self.fileno)
            if self.__conn_ev_flag:
                self.error()
                return
            ''''''
            self.__conn_ok = True
            self.connect_ok()
            return

        if self.writer.size() == 0:
            self.tcp_writable()
        if self.writer.size() == 0: return

        size = self.writer.size()

        try:
            sent_data = self.writer._getvalue()
            sent_size = self.send(sent_data)

            if size > sent_size:
                self.writer.write(sent_data[sent_size:])
                return
            if self.__delete_this_no_sent_data and self.writer.size() == 0:
                self.delete_handler(self.fileno)
                return
            self.tcp_writable()
        except BlockingIOError:
            return
        except ConnectionError:
            self.error()
        except FileNotFoundError:
            self.error()
        except TimeoutError:
            self.error()

    def send_now(self):
        """立刻发送数据
        :return:
        """
        if self.__is_async_socket_client and not self.is_conn_ok(): return
        self.evt_write()

    def timeout(self):
        if self.__is_async_socket_client and not self.is_conn_ok():
            self.unregister(self.fileno)

        self.tcp_timeout()

    def error(self):
        self.tcp_error()

    def delete(self):
        self.tcp_delete()

    def message_from_handler(self, from_fd, byte_data):
        """重写这个方法
        :param from_fd:
        :param args:
        :param kwargs:
        :return:
        """
        pass

    def reset(self):
        self.tcp_reset()

    def tcp_accept(self):
        """重写这个方法,接受客户端连接
        :return:
        """
        pass

    def tcp_readable(self):
        """重写这个方法
        :return:
        """
        pass

    def tcp_writable(self):
        """重写这个方法
        :return:
        """
        pass

    def tcp_timeout(self):
        """重写这个方法
        :return:
        """
        pass

    def tcp_error(self):
        """重写这个方法
        :return:
        """
        pass

    def tcp_delete(self):
        """重写这个方法
        :return:
        """
        pass

    def tcp_reset(self):
        pass

    def connect(self, address, timeout=3):
        self.__is_async_socket_client = True

        err = self.socket.connect_ex(address)

        if err:
            self.register(self.fileno)
            self.add_evt_read(self.fileno)
            self.add_evt_write(self.fileno)
            self.set_timeout(self.fileno, timeout)
            return

        self.connect_ok()
        self.__conn_ok = True

    def connect_ok(self):
        """连接成功后调用的函数,重写这个方法
        :return:
        """
        pass

    def is_conn_ok(self):
        return self.__conn_ok

    def delete_this_no_sent_data(self):
        """没有可发送的数据时候删除这个handler"""
        self.__delete_this_no_sent_data = True

    def getpeername(self):
        return self.socket.getpeername()

    def handle_tcp_received_data(self, received_data):
        """处理刚刚接收过来的数据包,该函数在socket.recv调用之后被调用
        :param received_data:
        :return bytes:
        """
        return received_data
