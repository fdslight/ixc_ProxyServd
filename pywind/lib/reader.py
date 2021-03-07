#!/usr/bin/env python3

import io


class reader(object):
    __size = 0
    __data_list = []
    __lifo_queue = None

    def __init__(self):
        self.__size = 0
        self.__data_list = []
        self.__lifo_queue = []

    def read(self, n=-1):
        if n == 0:
            return b""

        byte_io = io.BytesIO()

        remainN = n
        while 1:
            try:
                try:
                    byte_data = self.__lifo_queue.pop()
                except IndexError:
                    byte_data = self.__data_list.pop(0)

                # 可能在一些情况下,lifo_queue获取的byte_data的值为b"",因此要加入该行避免
                if not byte_data: byte_data = self.__data_list.pop(0)

                size = len(byte_data)

                if n < 0:
                    byte_io.write(byte_data)
                    continue

                if size < 1: break

                read = b""
                if remainN >= size:
                    remainN -= size
                    read = byte_data
                    byte_io.write(read)
                    continue
                read = byte_data[0:remainN]
                remain = byte_data[remainN:]

                byte_io.write(read)

                self.__lifo_queue.append(remain)
                break
            except IndexError:
                break

        ret = byte_io.getvalue()
        byte_io.close()

        self.__size -= len(ret)

        return ret

    def readlines(self, hint=None):
        seq = []

        while self.size() > 0:
            line = self.readline()

            if line != b"":
                seq.append(line)
            ''''''

        return seq

    def __iter__(self):
        return self

    def __next__(self):
        return self.readline()

    def readline(self, limit=-1):
        if limit == 0:
            return b""

        if limit > 0:
            byte_data = self.read(limit)
            find_pos = byte_data.find(b"\n")
            ret = byte_data

            if find_pos > -1:
                end = find_pos + 1
                ret = byte_data[0:end]
                begin = end
                remain = byte_data[begin:]

                self.__lifo_queue.put(remain)
                self.__size += len(remain)
            return ret

        byte_io = io.BytesIO()
        while 1:
            try:
                try:
                    byte_data = self.__lifo_queue.pop()
                except IndexError:
                    byte_data = self.__data_list.pop(0)

                size = len(byte_data)

                if size < 1:
                    break

                find_pos = byte_data.find(b"\n")

                if find_pos > -1:
                    end = find_pos + 1
                    read = byte_data[0:end]
                    begin = end
                    remain = byte_data[begin:]
                    self.__lifo_queue.append(remain)
                    self.__size += len(remain)
                    byte_io.write(read)
                    break

                byte_io.write(byte_data)

            except IndexError:
                break

        ret = byte_io.getvalue()
        byte_io.close()
        self.__size -= len(ret)

        return ret

    def push(self, byte_data):
        if byte_data == b"": return

        size = len(byte_data)

        self.__size += size
        self.__lifo_queue.append(byte_data)

    def _putvalue(self, byte_data):
        # cut down README.md list data
        # decreasing Memory Consumption
        if byte_data == b"":
            return

        size = len(byte_data)

        self.__data_list.append(byte_data)
        self.__size += size

    def size(self):
        return self.__size

    def flush(self):
        _ = self.read()
