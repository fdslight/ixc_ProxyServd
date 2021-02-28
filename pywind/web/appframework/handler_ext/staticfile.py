#!/usr/bin/env python3
"""实现静态文件文件功能"""

import pywind.web.appframework.app_handler as app_handler
import os, hashlib


class staticfile(app_handler.handler):
    __mime_map = None
    __file_object = None
    __is_responsed_header = False
    # 是否根据时间来生成304响应,默认根据文件MD5值
    __304_by_time = False

    # 是否通过修改时间来判断文件是否发生修改
    cmp_file_modify_by_mtime = False

    __file_size = 0
    __read_size = 0

    def initialize(self):
        self.__mime_map = {"bmp": "image/bmp", "gif": "image/gif", "jpe": "image/jpeg", "jpeg": "image/jpeg",
                           "jpg": "image/jpeg", "svg": "image/svg+xml;charset=utf-8", "ico": "image/x-icon",
                           "css": "text/css;charset=utf-8", "js": "text/javascript;charset=utf-8",
                           "woff": "application/font-woff", "ttf": "application/font-ttf",
                           "eot": "application/vnd.ms-fontobject", "otf": "application/font-otf",
                           "json": "application/json;charset=utf-8", "woff2": "application/font-woff2",
                           "png": "image/png", }
        self.__read_size = 0
        self.__file_size = 0
        self.__is_finish = False
        self.__is_responsed_header = False
        self.request.set_allow_methods(["GET"])
        self.staticfile_init()
        return True

    def set_mime(self, name, value):
        self.__mime_map[name] = value

    def staticfile_init(self):
        """重写这个方法"""
        pass

    def get_file_path(self):
        """重写这个方法"""
        return ""

    def handle(self):
        if not self.__file_object:
            fpath = self.get_file_path()
            self.__file_path = fpath

            if not os.path.isfile(fpath):
                self.set_status("404 Not Found")
                self.finish()
                return
            ext_name = self.get_file_ext_name(fpath).lower()

            if ext_name not in self.__mime_map:
                self.set_status("415 Unsupported Media Type")
                self.finish()
                return

            stat = os.stat(fpath)

            if self.cmp_file_modify_by_mtime:
                is_modified = self.__is_modified_by_mtime(stat.st_mtime)
            else:
                file_md5 = self.__calc_file_md5(fpath)
                if_none_match = self.request.environ.get("HTTP_IF_NONE_MATCH", "")
                is_modified = if_none_match == file_md5

            if is_modified:
                self.set_status("304 Not Modified")
                self.finish()
                return

            self.__file_size = stat.st_size
            self.__read_size = 0
            self.__file_object = open(fpath, "rb")

            self.set_status("200 OK")
            self.set_headers([("Content-Length", stat.st_size,), ("Content-Type", self.__mime_map[ext_name],),
                              ("Last-Modified", self.get_header_date(stat.st_mtime),), ])

            if not self.cmp_file_modify_by_mtime: self.set_header("Etag", file_md5)

        byte_data = self.__async_read_file()
        self.write(byte_data)

        if self.__file_size == self.__read_size: self.finish()

    def get_file_ext_name(self, path):
        """获取文件扩展名"""
        dirname = os.path.dirname(path)

        size = len(dirname)
        fname = path[size:]
        p = fname.find(".")

        if p < 0: return ""

        size = len(fname)
        n = size - 1
        seq = []

        while fname[n] != "." and n >= 0:
            seq.append(fname[n])
            n -= 1
        seq.reverse()
        return "".join(seq)

    def __async_read_file(self):
        """异步文件读取
        :return: file_data
        """
        rdata = self.__file_object.read(8192)
        self.__read_size += len(rdata)

        return rdata

    def release(self):
        if self.__file_object:
            self.__file_object.close()
        self.__file_object = None

    def __calc_file_md5(self, fpath):
        md5 = hashlib.md5()
        fdst = open(fpath, "rb")

        while 1:
            rdata = fdst.read(8192)
            if not rdata: break
            md5.update(rdata)
        fdst.close()

        return md5.hexdigest()

    def __is_modified_by_mtime(self, mtime):
        try:
            sts = self.request.environ["HTTP_IF_MODIFIED_SINCE"]
        except KeyError:
            return True

        t = self.get_time_from_header_date(sts)
        if t == None: return True

        return t == float(mtime)
