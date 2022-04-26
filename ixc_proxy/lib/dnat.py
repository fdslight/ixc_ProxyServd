#!/usr/bin/env python3

import os, json
import ixc_proxy.lib.logging as logging
import ixc_proxy.lib.base_proto.utils as proto_utils
import pywind.lib.netutils as netutils


def dnat_rule_parse(fpath: str):
    fdst = open(fpath, "r")
    is_err = False
    results = []

    for line in fdst:
        p = line.find("=")
        if p < 1:
            is_err = True
            logging.print_error("wrong dnat rule %s %s" % (fpath, line))
            break
        line = line.replace("\n", "")
        line = line.replace("\r", "")
        old_addr = line[0:p].strip()
        p += 1
        new_addr = line[p:].strip()
        if netutils.is_ipv4_address(old_addr) != netutils.is_ipv4_address(new_addr):
            is_err = True
            logging.print_error("wrong dnat rule %s %s" % (fpath, line))
            break

        if netutils.is_ipv6_address(old_addr) != netutils.is_ipv6_address(new_addr):
            is_err = True
            logging.print_error("wrong dnat rule %s %s" % (fpath, line))
            break

        if not netutils.is_ipv4_address(old_addr) and not netutils.is_ipv6_address(new_addr):
            is_err = True
            logging.print_error("wrong dnat rule %s %s" % (fpath, line))
            break

        if netutils.is_ipv4_address(old_addr):
            results.append((old_addr, new_addr, False,))
        else:
            results.append((old_addr, new_addr, True,))

    if is_err: return []

    return results


class dnat_rule(object):
    __rules = None

    @property
    def conf_dir(self):
        my_dir = os.path.dirname(__file__)
        config_path = "%s/../../ixc_configs" % my_dir
        return config_path

    def __init__(self):
        self.__rules = {}
        self.__tmp_rules = {}

    def get_user_configs(self):
        path = "%s/access.json" % self.conf_dir
        with open(path, "r") as f: s = f.read()
        f.close()
        configs = json.loads(s)

        return configs

    def get_rules(self):
        """获取规则改变
        :return {"del_list":[],"add_list":[]}
        """
        old_dict = {}
        new_dict = {}

        __list = []
        is_err = False

        user_configs = self.get_user_configs()
        for info in user_configs:
            user_name = info["username"]
            passwd = info["password"]
            dnat_enable = info.get("dnat_enable", False)
            dnat_rule_file = info.get("dnat_rule_file", "")

            user_id = proto_utils.gen_session_id(user_name, passwd)
            # 如果未在规则里面并且DNAT未开启那么忽略
            if not dnat_enable: continue
            fpath = "%s/%s" % (self.conf_dir, dnat_rule_file)
            if not os.path.isfile(fpath):
                logging.print_general("cannot find DNAT file %s for user %s" % (fpath, user_name,))
                continue
            results = dnat_rule_parse(fpath)
            # 检查是否存在规则冲突
            for old_addr, new_addr, is_ipv6 in results:
                if old_addr in old_dict:
                    is_err = True
                    logging.print_error("conflict rule %s=%s %s %s" % (old_addr, new_addr, old_dict[old_addr], fpath,))
                    break
                if new_addr in new_dict:
                    is_err = True
                    logging.print_error("conflict rule %s=%s %s %s" % (old_addr, new_addr, new_dict[new_addr], fpath,))
                    break

                old_dict[old_addr] = fpath
                new_dict[new_addr] = fpath

                __list.append((old_addr, new_addr, is_ipv6, user_id,))

        if is_err:
            return False, []
        return True, __list
