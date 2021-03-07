#!/usr/bin/env python3
"""核心语法解析器,实现核心语法解析功能
"""


class SyntaxErr(Exception): pass


class ParserErr(Exception): pass


### 对应文本类型
# 为普通文本
TYPE_TEXT = 0

# 为block
TYPE_BLOCK = 1

# 为Python代码
TYPE_PYCODE = 2

# 为python语法,即 ${xxx} 这样的字符串
TYPE_PYSYNTAX = 3


# 为include


class parser(object):
    def __get_quot_content(self, sts, quot):
        """
        :param sts: 
        :param quot: 是单引号还是双引号
        :return: 
        """
        p = sts.find(quot)
        if p < 0: return ""
        a = p + 1
        sts = sts[a:]
        p = sts.find(quot)
        if p < 0: return ""

        return sts[0:p]

    def __parse_block_tag_name_property(self, tag_content):
        """获取block标签的name属性,注意,block只能包含且必须包含name属性
        :param tag_content:块标签内容 
        :return: 
        """
        # 获取引号的内容
        name = self.__get_quot_content(tag_content, "\"")
        if not name:
            name = self.__get_quot_content(tag_content, "'")
        return name

    def __parse_single_syntax(self, sts):
        """解析美元符号
        :param sts: 
        :return: 
        """
        results = []

        while 1:
            pos = sts.find("${")
            if pos < 0:
                results.append((False, sts,))
                break
            s1 = sts[0:pos]
            if s1: results.append((False, s1,))
            pos += 2
            sts = sts[pos:]
            pos = sts.find("}")
            if pos < 1: raise SyntaxErr
            s2 = sts[0:pos]
            results.append((True, s2,))
            pos += 1
            sts = sts[pos:]

        return results

    def __parse_pycode_block(self, sts):
        results = []

        start = "<%"
        end = "%>"

        size_begin = 2
        size_end = 2

        while 1:
            pos = sts.find(start)
            if pos < 0:
                results.append((False, sts,))
                break
            s1 = sts[0:pos]
            if s1: results.append((False, s1,))

            pos += size_begin
            sts_bak = sts
            sts = sts[pos:]

            pos = sts.find(end)
            if pos < 0:
                results.append((False, sts_bak,))
                break

            results.append((True, sts[0:pos]))
            pos += size_end
            sts = sts[pos:]

        return results

    def __parse_tpl_block(self, sts):
        """解析模版块
        :param sts: 
        :return: 
        """
        results = []

        while 1:
            pos = sts.find("<%block")
            if pos < 0:
                results.append((False, sts))
                break

            t_sts = sts[pos:]
            t = t_sts.find(">")
            t += pos

            if t < 1:
                results.append((False, sts))
                break
            tt = t - 1
            t = t + 1

            s1 = sts[0:pos]
            s2 = sts[pos:t]

            if sts[tt] == "/":
                results.append((False, s1))
                results.append((True, (s2, "",),))
                sts = sts[t:]
                continue
            pos = sts.find("</%block>")

            if pos < 9:
                results.append((False, sts))
                break
            s3 = sts[t:pos]
            pos += 9
            results.append((False, s1,))
            results.append((True, (s2, s3,),))
            sts = sts[pos:]

        return results


    def __aligin_pycode(self, sts):
        """对齐Python代码
        :param sts: 
        :return: 
        """
        tmplist = sts.split("\n")
        aligned_results = []

        n = 0
        flags = False
        for s in tmplist:
            if not s:
                aligned_results.append(s)
                continue
            if not flags:
                while 1:
                    ch = s[n]
                    if ch != "\t" and ch != " ": break
                    n += 1
                flags = True
            aligned_results.append(s[n:])

        return "\n".join(aligned_results)

    def parse(self, sts):
        block_map = {}

        results = self.__parse_tpl_block(sts)

        tmp_seq_a = []

        # 首先处理block标签
        for flags, v in results:
            if flags:
                block_content, s = v
                name = self.__parse_block_tag_name_property(block_content)
                if name: block_map[name] = s
                tmp_seq_a.append((True, name,))
                continue
            tmp_seq_a.append((False, v,))

        # 处理Python代码块
        tmp_seq_b = []
        for flags, v in tmp_seq_a:
            if flags:
                tmp_seq_b.append((TYPE_BLOCK, v,))
                continue
            rs = self.__parse_pycode_block(v)
            for flags, v in rs:
                if flags:
                    tmp_seq_b.append((TYPE_PYCODE, self.__aligin_pycode(v)))
                else:
                    tmp_seq_b.append((TYPE_TEXT, v,))

        # 处理Python单个语句块
        tmp_seq_c = []
        for flags, v in tmp_seq_b:
            if flags != TYPE_TEXT:
                tmp_seq_c.append((flags, v,))
                continue
            rs = self.__parse_single_syntax(v)
            for flags, v in rs:
                if flags:
                    tmp_seq_c.append((TYPE_PYSYNTAX, v,))
                else:
                    tmp_seq_c.append((TYPE_TEXT, v))

        # 解析block内部的文字
        for k in block_map:
            t, _ = self.parse(block_map[k])
            block_map[k] = t

        return tmp_seq_c, block_map
