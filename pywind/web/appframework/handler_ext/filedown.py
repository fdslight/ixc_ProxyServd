#!/usr/bin/env python3
"""实现文件下载功能"""
import pywind.web.appframework.app_handler as app_handler
import os


class FileDownErr(Exception): pass


class filedown(app_handler.handler):
    __file_obj = None

    def __resend_file(self, fpath):
        """重新发送文件"""
        file_md5 = self.calc_file_md5(fpath)
        self.__file_obj = open(fpath, "rb")
        stat = os.stat(fpath)

        dirname = os.path.dirname(fpath)
        size = len(dirname)

        if fpath[size] == "/":
            n = size + 1
            filename = fpath[n:]
        else:
            filename = fpath[size]

        self.set_headers(
            [
                ("Content-Length", stat.st_size,),
                ("Accept-Ranges", "bytes",),
                ("Etag", file_md5,),
                ("Content-Type", "application/octet-stream",),
                ("Last-Modified", self.get_header_date(stat.st_mtime),),
                ("Content-Disposition", "attachment; filename=%s" % filename,),
            ]
        )
        self.set_status("200 OK")

    def __async_file_send(self):
        pass

    def handle(self):
        pass

    def __parse_request(self):
        """解析请求"""
        name = "HTTP_RANGE"

        if name not in self.request.environ: return (False, None, None, None,)

        file_range = self.request.environ[name]

    def __parse_file_range(self, file_range):
        if file_range[0:6] != "bytes=": return (False, None, None, None,)
        sts = file_range[6:]
        p = sts.find("-")

        if p < 1: return (False, None, None, None,)
        if sts[p] != "-": return (False, None, None, None,)

        try:
            start = int(sts[0:p])
        except ValueError:
            return (False, None, None, None,)

        p += 1
        sts = sts[p:]
        if not sts: return (True, start, None, None,)

        p = sts.find("/")
        if p == 0: return (False, None, None, None,)

        if p < 0:
            t = sts
        else:
            t = sts[0:p]

        try:
            end = int(t)
        except ValueError:
            return (False, None, None, None,)

        if p < 0: return (True, start, end, None)
        p += 1
        try:
            _sum = int(sts[p:])
        except ValueError:
            return (False, None, None, None,)

        return (True, start, end, _sum,)

    def release(self):
        if not self.__file_obj:
            self.__file_obj.close()
            self.__file_obj = None
        return
