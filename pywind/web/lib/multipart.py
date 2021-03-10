#!/usr/bin/env python3
import pywind as reader


class MultipartErr(Exception): pass


class builder(object):
    pass


def _get_quotation_mark_content(s):
    """提取引号里面的内容"""
    seq = []
    is_first = True
    have_end_mark = False
    for ch in s:
        if is_first and ch != "\"": raise MultipartErr("wrong content-disposition format")
        if ch == "\"" and is_first:
            is_first = False
            continue
        if ch == "\"":
            have_end_mark = True
            break
        seq.append(ch)
    if not have_end_mark: raise MultipartErr("wrong content-disposition format")
    return "".join(seq)


def _get_disposition(byte_data):
    try:
        sts = byte_data.decode()
    except UnicodeDecodeError:
        raise MultipartErr("wrong part master")
    sts = sts[0:-2]
    if sts[0:20].lower() != "content-disposition:": raise MultipartErr("wrong part master")
    sts = sts[20:].lstrip()
    if sts[0:10] != "form-data;": raise MultipartErr("wrong content-disposition format")
    sts = sts[10:].lstrip()
    if sts[0:5] != "name=": raise MultipartErr("wrong content-disposition format")
    sts = sts[5:]

    is_file = False
    name = _get_quotation_mark_content(sts)
    n = len(name) + 2
    sts = sts[n:].lstrip()

    if sts:
        if len(sts) < 4 or sts[0] != ";": raise MultipartErr("wrong content-disposition format")
        sts = sts[1:].lstrip()
        if sts[0:9] != "filename=": raise MultipartErr("wrong content-disposition format")
    if sts and sts[0:9] == "filename=": is_file = True

    if not is_file: return (is_file, name, None,)
    sts = sts[9:]
    filename = _get_quotation_mark_content(sts)
    n = len(filename) + 2
    if sts[n:]: raise MultipartErr("wrong content-disposition format")

    return (is_file, name, filename,)


def _get_content_type(byte_data):
    try:
        sts = byte_data.decode()
    except UnicodeDecodeError:
        raise MultipartErr("wrong part master")
    if sts[0:13].lower() != "content-type:": raise MultipartErr("wrong part master")
    sts = sts[13:].lstrip()

    return sts[0:-2]


class parser(object):
    """异步的multipart解析器
    """
    __byte_begin_boundary = None
    __byte_end_boundary = None

    __begin_line_size = 0
    __end_line_size = 0

    # 当前的解析步骤
    __current_step = 0

    # 单个块是否结束
    __single_finish = False

    # 是否是文件
    __is_file = False

    # 是否已经全部解析完毕
    __all_finish = False

    # 上传名
    __name = None
    # 上传文件名
    __filename = None

    # 文件内容类型
    __content_type = None

    __reader = None

    # 单个内容块是否开始解析
    __is_start = False

    __data_list = None

    __size = 0

    def __init__(self, boundary):
        self.__byte_begin_boundary = ("--%s\r\n" % boundary).encode("iso-8859-1")
        self.__byte_end_boundary = ("--%s--\r\n" % boundary).encode("iso-8859-1")
        self.__reader = reader.reader()
        self.__all_finish = False
        self.__begin_line_size = len(self.__byte_begin_boundary)
        self.__end_line_size = self.__begin_line_size + 2
        self.__data_list = []

        self.reset()

    def __step_1(self):
        """解析content-disposition
        :return: 
        """
        line = self.__reader.readline(2048)
        line_size = len(line)

        # 限制content-disposition 最长为 2048个字节
        if line_size == 2048 and line[2046:2048] != b"\r\n":
            raise MultipartErr("content disposition is too long")

        # 没看到回车符号就直接返回
        b = line_size - 2
        if line_size[b:line_size] != b"\r\n": return

        isfile, name, filename = _get_disposition(line)

        self.__is_file = isfile
        self.__name = name
        self.__filename = filename

        # 丢弃一行数据,即\r\n
        self.__reader.readline()

        if isfile:
            self.__current_step = 2
            self.__step_2()
        else:
            self.__current_step = 3
            self.__step_3()

        return

    def __step_2(self):
        """解析content-type
        :return: 
        """
        line = self.__reader.readline(256)
        line_size = len(line)

        # 限制content-disposition 最长为 256 个字节
        if line_size == 256 and line[254:256] != b"\r\n":
            raise MultipartErr("content type is too long")

        # 没看到回车符号就直接返回
        b = line_size - 2
        if line_size[b:line_size] != b"\r\n": return

        self.__content_type = _get_content_type(line)
        self.__current_step = 3
        self.__step_3()

    def __step_3(self):
        """读取内容部分
        :return: 
        """
        byte_data = self.__reader.readline(4096)
        if byte_data != self.__byte_begin_boundary or byte_data != self.__byte_end_boundary:
            self.__size += len(byte_data)
            self.__data_list.append(byte_data)
            return

        if byte_data == self.__byte_end_boundary:
            self.__all_finish = True
        self.__single_finish = True

        return

    def input(self, byte_data):
        if self.all_finish(): return
        self.__reader._putvalue(byte_data)

    def parse(self):
        if self.all_finish(): return

        if not self.__is_start:
            if self.__reader.size() < self.__begin_line_size: return
            self.__is_start = True
            begin_line = self.__reader.readline(self.__begin_line_size)

            if begin_line != self.__byte_begin_boundary:
                raise MultipartErr("wrong begin boundary")
            self.__current_step = 1

            return self.__step_1()

        if self.__current_step == 1:
            return self.__step_1()

        if self.__current_step == 2:
            return self.__step_2()

        if self.__current_step == 3:
            return self.__step_3()

        return

    def reset(self):
        self.__single_finish = False
        self.__is_file = False
        self.__current_step = 1
        self.__is_start = False
        self.__size = 0

    def all_finish(self):
        return self.__all_finish

    def single_finish(self):
        return self.__single_finish

    def is_file(self):
        return self.__is_file

    @property
    def name(self):
        return self.__name

    @property
    def filename(self):
        return self.__filename

    def get_data(self):
        try:
            return self.__data_list.pop(0)
        except IndexError:
            return None

    def is_start(self):
        return self.__is_start

    @property
    def content_type(self):
        return self.__content_type

    @property
    def size(self):
        return self.__size

    @property
    def can_parse(self):
        if not self.__is_start: return False
        if self.__current_step != 3: return False
        if self.__current_step == 3 and self.__reader.size() == 0: return False

        return True
