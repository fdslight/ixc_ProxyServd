#!/usr/bin/env python3
import os
import sys
import shutil
import pywind.lib.sys_build as sys_build


def write_kern_ver_to_file(fpath):
    """写入内核版本到文件
    :param fpath:
    :return:
    """
    with open(fpath, "w") as f:
        popen = os.popen("uname -r")
        f.write(popen.read())
        popen.close()


def __build_fn_utils(cflags):
    sys_build.do_compile(
        ["ixc_proxy/lib/fn_utils.c"], "ixc_proxy/lib/fn_utils.so", cflags, debug=True, is_shared=True
    )


def __build_fdsl_ctl(cflags):
    sys_build.do_compile(
        ["driver/fdsl_dgram/py_fdsl_ctl.c"], "ixc_proxy/lib/fdsl_ctl.so", cflags, debug=True, is_shared=True
    )


def build_server(cflags, kern_nat_mod=False):
    __build_fn_utils(cflags)
    __build_fdsl_ctl(cflags)

    build_cone_nat()


def build_cone_nat():
    """构建内核cone nat模块
    :return:
    """
    os.chdir("driver/netfilter-full-cone-nat")
    os.system("make clean")
    os.system("make")

    fname = "xt_FULLCONENAT.ko"
    fpath = "../%s" % fname

    if os.path.isfile(fpath):
        os.remove(fpath)
    if not os.path.isfile(fname):
        print("ERROR: please install linux kernel headers")
        return
    shutil.move(fname, fpath)

    os.chdir("../../")
    write_kern_ver_to_file("ixc_configs/kern_version")


def build_client(cflags, gw_mode=False):
    __build_fn_utils(cflags)
    __build_fdsl_ctl(cflags)

    if gw_mode:
        build_cone_nat()

        os.chdir("driver/fdsl_dgram")
        os.system("make clean")
        os.system("make")
        os.chdir("../../")
        write_kern_ver_to_file("ixc_configs/kern_version")
        if not os.path.isfile("driver/fdsl_dgram/fdslight_dgram.ko"):
            print("install fdslight failed!!!")
            return

        path = "driver/fdslight_dgram.ko"
        if os.path.isfile(path):
            os.remove(path)
        shutil.move("driver/fdsl_dgram/fdslight_dgram.ko", "driver")


def main():
    help_doc = """
    gateway | server | local   python3_include
    """

    argv = sys.argv[1:]
    if len(argv) != 2:
        print(help_doc)
        return

    mode = argv[0]

    if mode not in ("gateway", "server", "local",):
        print("the mode must be gateway,server or local")
        return

    if not os.path.isdir(argv[1]):
        print("not found directory %s" % argv[1])
        return

    cflags = " -I %s" % "".join(argv[1:])

    if mode == "gateway":
        build_client(cflags, gw_mode=True)
        return

    if mode == "server":
        build_server(cflags)
        return

    if mode == "local":
        build_client(cflags, gw_mode=False)


if __name__ == '__main__':
    main()
