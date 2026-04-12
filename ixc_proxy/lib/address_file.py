#!/usr/bin/env python3

# import sys
# sys.path.append("../../")

import pywind.lib.netutils as netutils


def parse_udp_heartbeat_address_from_file(fpath: str, is_ipv6=False):
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


def parse_address_list_from_file(fpath: str):
    err_address = []
    ok_address = []

    fdst = open(fpath, "r", encoding="utf-8")
    for line in fdst:
        line = line.strip()

        line = line.replace("\n", "")
        line = line.replace("\r", "")

        if not line: continue

        if line[0] == "#": continue

        p = line.find("/")
        prefix = ""
        if p < 1:
            addr = line
        else:
            addr = line[0:p]
            p += 1
            prefix = line[p:]

        if not netutils.is_ipv6_address(addr) and not netutils.is_ipv4_address(addr):
            err_address.append(line)
            continue

        if p < 1:
            if netutils.is_ipv6_address(addr):
                prefix = "128"
            else:
                prefix = "32"
            ''''''
        try:
            p = int(prefix)
        except ValueError:
            err_address.append(line)
            continue
        if p < 0:
            err_address.append(line)
            continue
        if netutils.is_ipv6_address(addr):
            if p > 128:
                err_address.append(line)
                continue
            ''''''
        else:
            if p > 32:
                err_address.append(line)
                continue
            ''''''
        is_ipv6 = netutils.is_ipv6_address(addr)
        addr = netutils.calc_subnet(addr, p, is_ipv6=is_ipv6)
        ok_address.append((addr, p, is_ipv6))

    if err_address:
        return False, err_address

    return True, ok_address


# is_ok,address=parse_from_file("../../ixc_configs/udp_heartbeat_address_example.txt")
# print(is_ok,address)

is_ok, ok_address = parse_address_list_from_file("../../ixc_configs/limit_source_address_example.txt")
print(is_ok, ok_address)
