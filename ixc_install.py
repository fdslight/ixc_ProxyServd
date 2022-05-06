#!/usr/bin/env python3
import os, sys

import pywind.lib.sys_build as sys_build


def build(cflags):
    files = sys_build.get_c_files("ixc_proxy/lib/clib")
    files += sys_build.get_c_files("pywind/clib")

    files+=[
        "pywind/clib/netif/linux_tuntap.c",
        "pywind/clib/netutils.c",
    ]

    sys_build.do_compile(files, "ixc_proxy/lib/proxy.so", cflags, is_shared=True)


def main():
    help_doc = """
    python3_include_path  [debug]
    """

    argv = sys.argv[1:]
    if len(argv) < 1:
        print(help_doc)
        return

    if len(argv) > 2:
        print(help_doc)
        return

    if not os.path.isdir(argv[0]):
        print("not found directory %s" % argv[0])
        return

    debug = False

    if len(argv) == 2:
        if argv[1] != "debug":
            print(help_doc)
            return
        debug = True

    if debug:
        cflags = " -I %s -DDEBUG -g -Wall" % argv[0]
    else:
        cflags = " -I %s -O3 -Wall" % argv[0]

    build(cflags)


if __name__ == '__main__':
    main()
