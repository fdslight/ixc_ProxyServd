#!/usr/bin/env python3
"""关系型数据库"""


class sql_helper(object):
    # 表前缀
    __data_list = None
    __prefix = ""

    def __init__(self, prefix):
        self.__data_list = []
        self.__prefix = prefix

    def select(self, seq):
        self.__data_list.append(
            "SELECT %s" % ",".join(seq)
        )
        return self

    def where(self, where):
        self.__data_list.append(" WHERE %s" % where)
        return self

    def from_(self, table):
        self.__data_list.append(
            " FROM %s%s" % (self.__prefix, table,)
        )
        return self

    def delete(self):
        self.__data_list.append(
            "DELETE"
        )
        return self

    def insert(self, table, **kwargs):
        self.__data_list += [
            "INSERT INTO ",
            "%s%s" % (self.__prefix, table),
        ]

        fields = []
        values = []
        for k, v in kwargs.items():
            fields.append(k)
            values.append(v)

        if fields: self.__data_list.append(
            " (%s)" % ",".join(fields)
        )
        self.__data_list.append(
            " VALUES (%s)" % ",".join([str(v) for v in values])
        )

        return self

    def update(self, table, **kwargs):
        seq = []
        for k, v in kwargs.items(): seq.append("%s=%s" % (k, v,))

        self.__data_list.append(
            "UPDATE %s%s SET %s" % (self.__prefix, table, ",".join(seq))
        )
        return self

    def get_sql(self):
        tmplist = []
        while 1:
            try:
                tmplist.append(self.__data_list.pop(0))
            except IndexError:
                break
        tmplist.append(";")
        return "".join(tmplist)

    def append(self, sts):
        self.__data_list.append(" %s" % sts)

        return self

    def limit(self, limit):
        self.__data_list.append(" LIMIT %s" % limit)
        return self

    def offset(self, offset):
        self.__data_list.append(" OFFSET %s" % offset)
        return self


def build_value_map(field_seq, value_seq):
    """Python默认返回tuple结果,没有包含字段,此函数生成 `字段->值`映射
    """
    length = len(field_seq)
    ret_dict = {}

    for n in range(length):
        field = field_seq[n]
        value = value_seq[n]
        ret_dict[field] = value

    return ret_dict
