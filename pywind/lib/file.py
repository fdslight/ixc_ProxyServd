#!/usr/bin/env python3
"""
"""

import os


class fdir_each(object):
    """文件目录遍历
    """
    __results = None

    def __init__(self):
        """基本文件目录
        """
        self.__results = []

    def __get_files(self, d):
        files = []
        dirs = []

        seq = os.listdir(d)

        for s in seq:
            path = "%s/%s" % (d, s,)
            if os.path.isdir(path):
                dirs.append(path)
            else:
                files.append(path)

        result = [files, dirs]

        return tuple(result)

    def gen_file_list(self, d):
        """获取基本目录下的所有文件信息
        """
        files, dirs = self.__get_files(d)
        self.__results += files

        if not dirs: return
        for s in dirs: self.gen_file_list(s)

    @property
    def results(self):
        return self.__results

"""
cls = fdir_each()
cls.gen_file_list("/Applications")
for r in cls.results:
    print(r)
"""
