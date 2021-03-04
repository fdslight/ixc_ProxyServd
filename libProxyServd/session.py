#!/usr/bin/env python3

class auth_base(object):
    """基本验证类
    """

    def __init__(self):
        pass

    def myinit(self, *args, **kwargs):
        """初始化函数,重写这个方法
        :param args:
        :param kwargs:
        :return:
        """
        pass

    def release(self):
        """释放资源,重写这个方法
        :return:
        """
        pass

    def do_auth(self, user_id: bytes):
        """执行验证,重写这个方法
        :param user_id:
        :return:
        """
        pass

    def recv_from_client(self, user_id: bytes, data_len: int):
        """重写这个方法
        :param user_id:
        :param data_len:
        :return Boolean: True表示认证通过,False表示失败
        """
        return True

    def send_to_client(self, user_id: bytes, data_len: int):
        """重写这个方法
        :param user_id:
        :param data_len:
        :return Boolean:True表示认证通过,False表示失败
        """
        return True


class context(object):
    """会话据柄
    """
    __fd = None
    __user_id = None

    __msg_queue = None

    def __init__(self, user_id: bytes, fd: int):
        """
        :param fd:
        """
        self.__fd = fd
        self.__user_id = user_id
        self.__msg_queue = []

    def set_fd(self, fd: int):
        self.__fd = fd

    def msg_queue_append(self, msg: bytes):
        """添加到消息队列尾部
        :param msg:
        :return:
        """
        self.__msg_queue.append(msg)

    def msg_queue_pop(self):
        """从消息队列中获取数据
        :return:
        """
        try:
            return self.__msg_queue.pop(0)
        except IndexError:
            return None

    def msg_queue_insert_to_first(self, byte_data: bytes):
        """插入到消息队列第一个
        :param byte_data:
        :return:
        """
        self.__msg_queue.insert(0, byte_data)
