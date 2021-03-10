#!/usr/bin/env python3
import re


class tag_filter(object):
    """HTML标签过滤"""
    # 保留模式,只保留给定的属性和标记
    MODE_RETAIN = 1
    # 丢弃模式,丢弃给定的属性和标记
    MODE_DROP = 2

    __mode = MODE_DROP
    __text = None

    filter_tag_list = None
    filter_property_list = None

    def __init__(self, text, filter_mode=MODE_DROP):
        self.__mode = filter_mode
        self.__text = text

        self.filter_property_list = []
        self.filter_tag_list = []

    def change_mode(self, mode):
        """改变过滤模式"""
        self.__mode = mode
        self.filter_property_list = []
        self.filter_tag_list = []

    def __drop_tag(self):
        pass

    def __drop_property(self):
        pass

    def filter(self):
        """执行过滤"""
        pass

    def get_result(self):
        """获取过滤结果"""
        pass

    def __get_syntax_tree(self, sts):
        """获取标签语法树
        :param sts: 
        :return: 
        """
        pass