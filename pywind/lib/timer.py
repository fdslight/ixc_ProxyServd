#!/usr/bin/env python3

import time


class timer(object):
    __timeout_info = None
    __timeout_info_reverse = None
    __time_list = None

    def __init__(self):
        self.__timeout_info = {}
        self.__timeout_info_reverse = {}
        self.__time_list = []

    def get_timeout_names(self):
        cur_t = int(time.time())
        names = []

        while 1:
            try:
                t = self.__time_list.pop(0)
            except IndexError:
                break
            if t - cur_t > 0:
                self.__time_list.insert(0, t)
                break

            if t not in self.__timeout_info_reverse: continue
            pydict = self.__timeout_info_reverse[t]
            for k in pydict: names.append(k)

        tmpdict = {}
        for name in names:
            if name in tmpdict: continue
            tmpdict[name] = None

        results = []
        for k in tmpdict: results.append(k)

        return results

    def set_timeout(self, name, seconds=1):
        t = int(time.time()) + seconds
        old_t = 0
        if seconds < 1: return
        if name in self.__timeout_info:
            old_t = self.__timeout_info[name]
            del self.__timeout_info_reverse[old_t][name]
            if not self.__timeout_info_reverse[old_t]: del self.__timeout_info_reverse[old_t]

        self.__timeout_info[name] = t

        if t not in self.__timeout_info_reverse:
            self.__timeout_info_reverse[t] = {}

        self.__timeout_info_reverse[t][name] = None
        # 防止过多的生成相同的timeout
        if old_t != t: self.__time_list.append(t)
        self.__time_list.sort()

    def exists(self, name):
        return (name in self.__timeout_info)

    def drop(self, name):
        t = self.__timeout_info[name]
        del self.__timeout_info_reverse[t][name]
        del self.__timeout_info[name]
        if not self.__timeout_info_reverse[t]: del self.__timeout_info_reverse[t]

    def get_min_time(self):
        cur_t = int(time.time())
        if not self.__time_list: return 0

        return self.__time_list[0] - cur_t
