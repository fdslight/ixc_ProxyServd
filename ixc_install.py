#!/usr/bin/env python3
import os, sys

import pywind.lib.sys_build as sys_build


def find_python_include_path():
    files = os.listdir("/usr/include")
    result = ""

    for f in files:
        p = f.find("python3")
        if p < 0: continue
        result = "/usr/include/%s" % f
        break

    return result


def build(cflags):
    files = sys_build.get_c_files("ixc_proxy/lib/clib")
    files += sys_build.get_c_files("pywind/clib")

    files += [
        "pywind/clib/netif/linux_tuntap.c",
    ]

    sys_build.do_compile(files, "ixc_proxy/lib/proxy.so", cflags, is_shared=True)


def main():
    help_doc = """
    [python3_include_path]  [debug]
    """
    argv = sys.argv[1:]

    python3_include = ""
    debug = False

    if len(argv) == 1:
        if argv[0] == "debug":
            debug = True
        else:
            python3_include = argv[0]

    elif len(argv) == 2:
        python3_include = argv[0]
        if argv[1] != "debug":
            print(help_doc)
            return
        debug = True
    elif len(argv) == 0:
        pass
    else:
        print(help_doc)
        return

    if not python3_include: python3_include = find_python_include_path()

    if not os.path.isdir(python3_include):
        print("ERROR:not found python3 header file %s" % python3_include)
        return

    if debug:
        cflags = " -I %s -DDEBUG -g -Wall" % python3_include
    else:
        cflags = " -I %s -O3 -Wall -march=native" % python3_include

    build(cflags)


if __name__ == '__main__':
    main()
