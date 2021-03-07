#!/usr/bin/env python3

import struct, os


def write_pid(file_path, pid):
    with open(file_path, "wb") as f:
        f.write(struct.pack("i", pid))
    f.close()


def get_pid(file_path):
    if not os.path.isfile(file_path): return -1

    with open(file_path, "rb") as f:
        pid, = struct.unpack("i", f.read())
    f.close()

    return pid
