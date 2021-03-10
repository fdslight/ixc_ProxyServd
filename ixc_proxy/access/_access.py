#!/usr/bin/env python3
import pywind.lib.timer as timer
import ixc_proxy.lib.logging as logging
import ixc_proxy.lib.base_proto.utils as proto_utils


class access(object):
    __timer = None
    __sessions = None
    # 会话超时时间
    __SESSION_TIMEOUT = 800

    __dispatcher = None

    def __init__(self, dispatcher):
        self.__timer = timer.timer()
        self.__sessions = {}
        self.__dispatcher = dispatcher

        self.init()

    def init(self):
        """初始化函数,重写这个方法"""
        pass

    def handle_recv(self, fileno, session_id, address, data_len):
        """处理数据的接收
        :param session_id,会话ID
        :param address,用户地址
        :param data_len,数据长度
        :return Boolean,True表示允许接受数据,False表示抛弃数据
        """
        return True

    def handle_send(self, session_id, data_len):
        """处理数据的发送
        :param session_id,会话ID
        :param data_len,数据长度
        :return Boolean,True表示允许发送数据,False表示抛弃数据
        """
        return True

    def handle_access_loop(self):
        """此函数会被循环调用,重写这个方法"""
        pass

    def handle_close(self, session_id):
        """处理会话关闭"""
        pass

    def add_session(self, fileno, username, session_id, address, priv_data=None):
        """加入会话
        :param fileno:文件描述符
        :param username:用户名
        :param session_id: 会话ID
        :param address: (ipaddr,port)
        :param priv_data:你的私有数据,如果想要修改数据,priv_data应该是引用类型
        :return:
        """
        if self.session_exists(session_id): return

        self.__sessions[session_id] = [fileno, username, address, {}, priv_data]
        self.__timer.set_timeout(session_id, self.__SESSION_TIMEOUT)
        self.__dispatcher.tell_register_session(session_id)
        logging.print_general("add_session:%s" % username, address)

    def get_session_info(self, session_id):
        if session_id not in self.__sessions: return None

        return tuple(self.__sessions[session_id])

    def del_session(self, session_id):
        """删除会话
        :param session_id:
        :return:
        """
        if session_id not in self.__sessions: return

        self.__timer.drop(session_id)
        self.handle_close(session_id)
        fileno, username, address, priv_data = self.__sessions[session_id]
        self.__dispatcher.tell_unregister_session(session_id, fileno)

        logging.print_general("del_session:%s" % username, address)
        del self.__sessions[session_id]

    def modify_session(self, session_id, fileno, address):
        """修改地址和文件描述符信息,如果没有变化则不修改
        :param session_id:
        :param address:
        :return:
        """
        a = "%s-%s" % address
        b = "%s-%s" % (self.__sessions[session_id][2])

        if a != b:
            self.__sessions[session_id][2] = address
        self.__sessions[session_id][0] = fileno

    def session_exists(self, session_id):
        return session_id in self.__sessions

    def gen_session_id(self, username, password):
        """生成用户session id
        :param username:
        :param password:
        :return:
        """
        return proto_utils.gen_session_id(username, password)

    def access_loop(self):
        names = self.__timer.get_timeout_names()
        for name in names:
            if not self.__timer.exists(name): continue
            self.del_session(name)
        return

    def data_for_send(self, session_id, pkt_len):
        b = self.handle_send(session_id, pkt_len)
        if b: self.__timer.set_timeout(session_id, self.__SESSION_TIMEOUT)

        return b

    def data_from_recv(self, fileno, session_id, address, pkt_len):
        b = self.handle_recv(fileno, session_id, address, pkt_len)

        if b:
            self.modify_session(session_id, fileno, address)
        return b

    def handle_user_change_signal(self):
        """重写这个方法,处理用户信息改变的信号
        :return:
        """
        pass

    def udp_add(self, session_id: bytes, address: tuple, fileno: int):
        _id = "%s-%s" % address
        info = self.__sessions[session_id][3]
        info[_id] = fileno

    def udp_del(self, session_id: bytes, address: tuple):
        _id = "%s-%s" % address
        info = self.__sessions[session_id][3]
        if _id in info: del info[_id]

    def udp_get(self, session_id: bytes, address: tuple):
        _id = "%s-%s" % address
        info = self.__sessions[session_id][3]

        return info.get(_id, -1)
