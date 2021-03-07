#!/usr/bin/env python3

import struct, os


def write_pid_to_file(fpath, pid):
    """写入pid到文件
    :param fpath:
    :param pid:
    :return:
    """
    with open(fpath, "wb") as f:
        f.write(struct.pack("i", pid))
    f.close()


def read_pid_from_file(fpath):
    """从文件读取pid
    :param fpath:
    :return:
    """
    pid = -1
    if not os.path.isfile(fpath):
        return pid

    with open(fpath, "rb") as f:
        data = f.read()
    f.close()

    pid, = struct.unpack("i", data)

    return pid
