#!/usr/bin/env python3
import io


class writer(object):
    __buff_queue = None
    __size = 0
    __lifo = None

    def __init__(self):
        self.__buff_queue = []
        self.__lifo = []
        self.__size = 0

    def is_empty(self):
        if self.__size < 1:
            return True

        return False

    def write(self, bdata):
        size = len(bdata)

        self.__buff_queue.append(bdata)
        self.__size += size

    def writeline(self, bdata=b""):
        byteio = io.BytesIO()
        writes = [bdata, "\r\n".encode("utf-8")]

        for v in writes:
            byteio.write(v)

        bdata = byteio.getvalue()
        byteio.close()

        self.write(bdata)

    def writelines(self, byte_list):
        byteio = io.BytesIO()

        for v in byte_list:
            byteio.write(v)
            byteio.write("\r\n".encode("utf-8"))

        bdata = byteio.getvalue()
        byteio.close()

        self.write(bdata)

    def push(self, byte_data):
        # cut down README.md list data
        # decreasing Memory Consumption
        if byte_data == b"":
            return

        self.__size += len(byte_data)
        self.__lifo.append(byte_data)

    def _getvalue(self):
        byte_io = io.BytesIO()

        while 1:
            try:
                v = self.__lifo.pop()
            except IndexError:
                try:
                    v = self.__buff_queue.pop(0)
                except IndexError:
                    break
                ''''''

            byte_io.write(v)

        ret = byte_io.getvalue()
        byte_io.close()
        self.__size = 0

        return ret

    def flush(self):
        _ = self._getvalue()

    def size(self):
        return self.__size
