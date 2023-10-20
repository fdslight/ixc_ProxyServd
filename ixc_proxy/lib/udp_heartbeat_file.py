#!/usr/bin/env python3

import pywind.lib.netutils as netutils


def parse_from_file(fpath: str, is_ipv6=False):
    err_address = []
    ok_address = []

    fdst = open(fpath, "r", encoding="utf-8")
    for line in fdst:
        line = line.strip()

        line = line.replace("\n", "")
        line = line.replace("\r", "")

        if not line: continue

        if line[0] == "#": continue

        p = line.find(",")
        if p < 1:
            err_address.append(line)
            continue

        caddr = line[0:p]
        p += 1
        port = line[p:]

        if not netutils.is_port_number(port):
            err_address.append(line)
            continue

        if is_ipv6 and not netutils.is_ipv6_address(caddr):
            err_address.append(line)
            continue

        if not is_ipv6 and not netutils.is_ipv4_address(caddr):
            err_address.append(line)
            continue

        ok_address.append((caddr, int(port),))

    if err_address:
        return False, err_address

    return True, ok_address

# is_ok,address=parse_from_file("../../ixc_configs/udp_heartbeat_address_example.txt")
# print(is_ok,address)
