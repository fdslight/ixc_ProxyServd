#!/usr/bin/env python3

class IniFileFmtErr(Exception): pass


class _Iniparser(object):
    def __drop_comment(self, seq):
        """去除注释"""
        line_n = 0
        rs = []

        for s in seq:
            line_n += 1

            # 去除空行
            t = s.rstrip()
            t = t.replace("\t", "")

            if not t: continue

            if t[0] == " ": raise IniFileFmtErr(s)
            if t[0] == "=": raise IniFileFmtErr(s)
            if t[0] == ";": continue
            if t[0] == "#": continue
            rs.append(t)

        return rs

    def __get_key_val(self, s):
        pos = s.find("=")
        if pos < 1: return None
        name = s[0:pos].rstrip()
        pos += 1
        value = s[pos:].lstrip()

        return (name, value,)

    def __get_result(self, seq):
        result = {}
        name = ""
        for s in seq:
            s = s.rstrip()
            if s[0] == "[":
                s = s.replace("[", "")
                s = s.replace("]", "")
                name = s
                continue
            rs = self.__get_key_val(s)
            if not rs: continue
            k, v = rs
            if name not in result: result[name] = {}
            result[name][k] = v

        return result

    def __split(self, sts):
        """对数据进行分割"""
        sts = sts.replace("\r", '')
        seq = sts.split("\n")

        return seq

    def parse(self, sts):
        seq = self.__split(sts)
        seq = self.__drop_comment(seq)
        result = self.__get_result(seq)

        return result


def ini_parse_from_file(fpath):
    with open(fpath, "rb") as f:
        data = f.read().decode("iso-8859-1")
    f.close()

    p = _Iniparser()
    return p.parse(data)


def ini_parse_from_sts(sts):
    p = _Iniparser()

    return p.parse(sts)


def save_to_ini(_dict: dict, fpath: str):
    """保存特定的字典对象到ini文件
    """
    seq = []

    for x in _dict:
        o = _dict[x]
        seq.append("[%s]\r\n" % x)
        for name, value in o.items():
            s = "%s = %s\r\n" % (name, value,)
            seq.append(s)
        ''''''

    w = "".join(seq)
    with open(fpath, "w") as f:
        f.write(w)
    f.close()
