#!/usr/bin/env python3
import os
import sys
import shutil
import pywind.lib.sys_build as sys_build


def __build_fn_utils(cflags):
    sys_build.do_compile(
        ["ixc_proxy/lib/fn_utils.c"], "ixc_proxy/lib/fn_utils.so", cflags, debug=True, is_shared=True
    )


def build(cflags):
    __build_fn_utils(cflags)


def main():
    help_doc = """
    python3_include_path
    """

    argv = sys.argv[1:]
    if len(argv) != 2:
        print(help_doc)
        return

    mode = argv[0]

    if not os.path.isdir(argv[1]):
        print("not found directory %s" % argv[1])
        return

    cflags = " -I %s" % "".join(argv[1:])


if __name__ == '__main__':
    main()
