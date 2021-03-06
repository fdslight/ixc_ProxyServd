#!/usr/bin/env python3

import time, traceback, sys


def print_general(text, address):
    s1 = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    print("%s\t%s:%s\t%s" % (text, address[0], address[1], s1))
    sys.stdout.flush()


def print_error(text=""):
    s1 = "<error time='%s'>" % time.strftime("%Y-%m-%d %H:%M:%S %Z")
    s2 = "</error>"

    if text:
        text = "%s\r\n%s\r\n%s\r\n" % (s1, text, s2,)
        sys.stderr.write(text)
    else:
        excpt = traceback.format_exc()
        error = "%s\r\n%s\r\n%s" % (s1, excpt, s2)
        sys.stderr.write(error)
    sys.stderr.flush()
