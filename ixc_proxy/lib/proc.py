#!/usr/bin/env python3
import os


def write_pid(fpath):
    pid = str(os.getpid())
    with open(fpath, "w") as f: f.write(pid)


def get_pid(fpath):
    if not os.path.isfile(fpath): return -1

    with open(fpath, "r") as f:
        pid = int(f.read())

    return pid
