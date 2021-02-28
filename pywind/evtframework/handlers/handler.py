#!/usr/bin/env python3

from pywind.global_vars import global_vars
import pywind.evtframework.consts as consts


class handler(object):
    __fileno = -1

    def set_fileno(self, fd):
        """设置这个处理者所对应的fd"""
        self.__fileno = fd

    @property
    def fileno(self):
        return self.__fileno

    def init_func(self, creator_fd, *args, **kwargs):
        """初始化函数,当对象实例后框架调用的函数
        :param creator_fd:创建者文件描述符
        :return fd:文件描述符,注意此描述符必须唯一
        """
        pass

    def evt_read(self):
        """
        读事件, 重写这个方法
        :return:
        """

    pass

    def evt_write(self):
        """
        写事件, 重写这个方法
        :return:
        """
        pass

    def timeout(self):
        """
        时间超时, 重写这个方法
        :return:
        """
        pass

    def error(self):
        """
        故障, 重写这个方法
        :return:
        """
        pass

    def delete(self):
        """
        最一些对象销毁的善后工作, 重写这个方法
        :return:
        """
        pass

    def set_timeout(self, fd, seconds):
        self.dispatcher.set_timeout(fd, seconds)

    def create_handler(self, creator_fd, h, *args, **kwargs):
        return self.dispatcher.create_handler(creator_fd, h, *args, **kwargs)

    def replace_handler(self, creator_fd, fileno, h, *args, **kwargs):
        return self.dispatcher.repleace_handler(creator_fd, fileno, h, *args, **kwargs)

    def delete_handler(self, fd):
        self.dispatcher.delete_handler(fd)

    def send_message_to_handler(self, src_fd, dst_fd, data):
        return self.dispatcher.send_message_to_handler(src_fd, dst_fd, data)

    def message_from_handler(self, from_fd, data):
        """
        重写这个方法, 当其他的处理者发送消息会调用这个函数
        :return:
        """
        pass

    def handler_exists(self, fd):
        return self.dispatcher.handler_exists(fd)

    def register(self, fd):
        self.dispatcher.register(fd)

    def add_evt_read(self, fd):
        self.dispatcher.add_evt_read(fd)

    def remove_evt_read(self, fd):
        self.dispatcher.remove_evt_read(fd)

    def add_evt_write(self, fd):
        self.dispatcher.add_evt_write(fd)

    def remove_evt_write(self, fd):
        self.dispatcher.remove_evt_write(fd)

    def unregister(self, fd):
        self.dispatcher.unregister(fd)

    @property
    def dispatcher(self):
        """
        获取分发器
        :return:
        """
        return global_vars[consts.SERVER_INSTANCE_NAME]

    def reset(self):
        """
        重置资源, 用于实现对象的重复利用, 重写这个方法
        :return:
        """
        pass

    def ctl_handler(self, src_fd, dst_fd, cmd, *args, **kwargs):
        """
        控制其它handler的行为
        :param dst_fd:
        :param cmd:
        :param args:
        :param kwargs:
        :return:
        """
        return self.dispatcher.ctl_handler(src_fd, dst_fd, cmd, *args, **kwargs)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        """
        handler控制命令, 当此其它handler需要控制此handler的时候, 此函数将会被调用
        :param dst_fd:
        :param cmd:
        :param args:
        :param kwargs:
        :return:
        """
        pass

    def add_to_loop_task(self, fileno):
        self.dispatcher.add_to_loop_task(fileno)

    def del_loop_task(self, fileno):
        self.dispatcher.del_loop_task(fileno)

    def task_loop(self):
        """任务循环函数,当把handler加入道task loop,就会循环调用此函数"""
        pass

    def release_when_replace(self):
        """当handler被替换的时候释放资源的函数
        :return:
        """
        pass

    def get_handler(self, fd):
        return self.dispatcher.get_handler(fd)
