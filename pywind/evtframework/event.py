#!/usr/bin/env python3
import select, time
import sys

EV_TYPE_READ = 1
EV_TYPE_WRITE = 2
EV_TYPE_NO_EV = 0


class event(object):
    """
    some descriptions:
    about standard events:
        epoll,kqueue,select will be converted standard events,the format is:
            [(fd,event_type,user_data),...]
    """
    __wlist = []
    __rlist = []

    # kqueue || epoll || select
    __async_mode = ""
    __epoll_object = None

    __kqueue_object = None
    __kqueue_event_map = {}
    # the data for changed event
    __kqueue_change_event_map = {}

    # {fd1:value1,fd2,value2,...}
    __epoll_register_info = {}

    # {fd1:True | False,...}
    __is_register = {}

    __poll_timeout = 0
    __iowait_func = None

    __users_data = {}

    def __init__(self, force_select=False):
        platform = sys.platform

        if force_select:
            self.__async_mode = "select"
            self.__iowait_func = self.__select_iowait
            return

        if platform.find("win32") > -1 or platform.find("cygwin") > -1:
            self.__async_mode = "select"
            self.__iowait_func = self.__select_iowait

        if platform.find("darwin") > -1 or platform.find("freebsd") > -1:
            self.__async_mode = "kqueue"
            self.__kqueue_object = select.kqueue()
            self.__iowait_func = self.__kqueue_iowait

        if platform.find("linux") > -1:
            self.__async_mode = "epoll"
            self.__epoll_object = select.epoll()
            self.__iowait_func = self.__epoll_iowait

        return

    def __del_ev_write(self, fileno):
        if fileno in self.__wlist:
            self.__wlist.remove(fileno)

        if self.__async_mode == "epoll":
            if fileno not in self.__epoll_register_info:
                return
            eventmask = self.__epoll_register_info[fileno]
            eventmask = eventmask & (~select.EPOLLOUT)

            self.__epoll_object.modify(fileno, eventmask)
            self.__epoll_register_info[fileno] = eventmask
            ''''''

        if self.__async_mode == "kqueue":
            if fileno not in self.__kqueue_event_map:
                return

            kevent = self.__kqueue_event_map[fileno]
            write_exists = (kevent.udata & EV_TYPE_WRITE) == EV_TYPE_WRITE

            if fileno not in self.__kqueue_change_event_map:
                self.__kqueue_change_event_map[fileno] = []

            if write_exists:
                kevent.filter = select.KQ_FILTER_WRITE
                kevent.flags = select.KQ_EV_DELETE
                kevent.udata = (kevent.udata & (~EV_TYPE_WRITE))

                self.__kqueue_change_event_map[fileno].append(kevent)
            ''''''
        return

    def __del_ev_read(self, fileno):

        if fileno in self.__rlist:
            self.__rlist.remove(fileno)

        if self.__async_mode == "epoll":
            if fileno not in self.__epoll_register_info:
                return

            eventmask = self.__epoll_register_info[fileno]
            eventmask = eventmask & (~select.EPOLLIN)

            self.__epoll_object.modify(fileno, eventmask)
            self.__epoll_register_info[fileno] = eventmask

        if self.__async_mode == "kqueue":
            if fileno not in self.__kqueue_event_map:
                return

            if fileno not in self.__kqueue_change_event_map:
                self.__kqueue_change_event_map[fileno] = []

            kevent = self.__kqueue_event_map[fileno]
            read_exists = (kevent.udata & EV_TYPE_READ) == EV_TYPE_READ

            if read_exists:
                kevent.filter = select.KQ_FILTER_READ
                kevent.flags = select.KQ_EV_DELETE

                self.__kqueue_change_event_map[fileno].append(kevent)
            ''''''
        return

    def __clean(self, fd):
        event_fd = fd

        if event_fd in self.__rlist:
            self.__rlist.remove(event_fd)

        if event_fd in self.__wlist:
            self.__wlist.remove(event_fd)

        if event_fd in self.__epoll_register_info:
            self.__epoll_object.unregister(event_fd)

            del self.__epoll_register_info[event_fd]

        if event_fd in self.__kqueue_event_map:
            del self.__kqueue_event_map[event_fd]

        if event_fd in self.__kqueue_change_event_map:
            del self.__kqueue_change_event_map[event_fd]

        if event_fd in self.__is_register:
            del self.__is_register[event_fd]

        return

    def __convert_epoll_events(self, events):
        """
        Convert epoll events to standard events
        """
        std_events = []

        for fileno, event in events:
            is_read = (event & select.EPOLLIN) == select.EPOLLIN
            is_write = (event & select.EPOLLOUT) == select.EPOLLOUT

            std_event = 0

            if is_read: std_event |= EV_TYPE_READ
            if is_write: std_event |= EV_TYPE_WRITE

            std_events.append((fileno, std_event, self.__users_data.get(fileno, None)))

        return std_events

    def __convert_kqueue_events(self, events):
        """
        Convert kqueue events to standard events
        """
        std_events = []
        for kevent in events:
            std_event = 0

            ident = kevent.ident
            flags = kevent.flags
            fflags = kevent.fflags
            filter_ = kevent.filter
            data = kevent.data
            udata = kevent.udata

            is_read = (filter_ & select.KQ_FILTER_READ) == select.KQ_FILTER_READ
            is_write = (filter_ & select.KQ_FILTER_WRITE) == select.KQ_FILTER_WRITE and (
                    (udata & EV_TYPE_WRITE) == EV_TYPE_WRITE)

            if is_read: std_event |= EV_TYPE_READ
            if is_write: std_event |= EV_TYPE_WRITE

            self.__kqueue_event_map[ident] = kevent

            std_events.append((ident, std_event, self.__users_data.get(ident, None)))

        return std_events

    def __convert_select_events(self, rlist, wlist, errlist):
        """
        Convert select events to standard events
        """
        std_events = []
        events_map = {}

        for fd in rlist:
            if fd not in events_map:
                events_map[fd] = 0

            events_map[fd] |= EV_TYPE_READ

        for fd in wlist:
            if fd not in events_map:
                events_map[fd] = 0

            events_map[fd] |= EV_TYPE_WRITE

        for fd in errlist:
            if fd not in events_map:
                events_map[fd] = 0

        for key in events_map:
            udata = self.__users_data.get(key, None)
            std_events.append((key, events_map[key], udata))

        return std_events

    def __handle_epoll_events(self, events):
        return self.__convert_epoll_events(events)

    def __epoll_iowait(self):
        events = self.__epoll_object.poll(self.__poll_timeout)

        return self.__handle_epoll_events(events)

    def __handle_kqueue_events(self, events):
        for kevent in events:
            ident = kevent.ident
            self.__kqueue_event_map[ident] = ident

        return self.__convert_kqueue_events(events)

    def __kqueue_iowait(self):
        changelist = []

        for key in self.__kqueue_change_event_map:
            kevents = self.__kqueue_change_event_map[key]

            changelist += kevents
        ''''''
        self.__kqueue_event_map = {}
        self.__kqueue_change_event_map = {}

        events = self.__kqueue_object.control(changelist, 100, self.__poll_timeout)

        return self.__handle_kqueue_events(events)

    def __handle_select_events(self, rlist, wlist, errlist):
        return self.__convert_select_events(rlist, wlist, errlist)

    def __select_iowait(self):
        rlist, wlist, errlist = select.select(self.__rlist, self.__wlist, [], self.__poll_timeout)

        return self.__handle_select_events(rlist, wlist, errlist)

    def __add_ev_read(self, fileno):
        """
        Note:if the event exists,it will not do anything
        """
        if fileno not in self.__rlist and self.__async_mode == "select":
            self.__rlist.append(fileno)

        if self.__async_mode == "epoll":
            if fileno not in self.__epoll_register_info:
                self.__epoll_register_info[fileno] = None

            eventmask = self.__epoll_register_info[fileno]
            event = select.EPOLLIN

            if eventmask == None:
                eventmask = event

                self.__epoll_object.register(fileno, eventmask)
                self.__epoll_register_info[fileno] = eventmask

                return

            is_register_read = (eventmask & select.EPOLLIN) == select.EPOLLIN

            if is_register_read == False:
                eventmask = event | eventmask
                self.__epoll_object.modify(fileno, eventmask)

        if self.__async_mode == "kqueue":
            filter_ = select.KQ_FILTER_READ
            flags = select.KQ_EV_ADD | select.KQ_EV_ENABLE

            if fileno not in self.__kqueue_event_map:
                kevent = select.kevent(fileno, filter_, flags)
                kevent.udata = 0
            else:
                kevent = self.__kqueue_event_map[fileno]

            read_exists = (kevent.udata & EV_TYPE_READ) == EV_TYPE_READ

            if read_exists == False:
                kevent.filter = filter_
                kevent.udata = (kevent.udata | EV_TYPE_READ)
                kevent.flags = flags

                if fileno not in self.__kqueue_change_event_map:
                    self.__kqueue_change_event_map[fileno] = []

                self.__kqueue_change_event_map[fileno].append(kevent)
            ''''''

        return

    def __add_ev_write(self, fileno):
        if fileno not in self.__wlist and self.__async_mode == "select":
            self.__wlist.append(fileno)

        if self.__async_mode == "epoll":
            if fileno not in self.__epoll_register_info:
                self.__epoll_register_info[fileno] = None

            eventmask = self.__epoll_register_info[fileno]
            event = select.EPOLLOUT

            if eventmask == None:
                eventmask = event

                self.__epoll_object.register(fileno, eventmask)
                self.__epoll_register_info[fileno] = eventmask

                return

            is_register_write = (eventmask & select.EPOLLOUT) == select.EPOLLOUT

            if is_register_write == False:
                eventmask = event | eventmask
                self.__epoll_object.modify(fileno, eventmask)

        if self.__async_mode == "kqueue":
            filter_ = select.KQ_FILTER_WRITE
            flags = select.KQ_EV_ADD | select.KQ_EV_ENABLE

            if fileno not in self.__kqueue_event_map:
                kevent = select.kevent(fileno, filter_, flags)
                kevent.udata = 0
            else:
                kevent = self.__kqueue_event_map[fileno]

            write_exists = (kevent.udata & EV_TYPE_WRITE) == EV_TYPE_WRITE

            if write_exists == False:
                kevent.filter = filter_
                kevent.flags = flags
                kevent.udata = (kevent.udata | EV_TYPE_WRITE)

                if fileno not in self.__kqueue_change_event_map:
                    self.__kqueue_change_event_map[fileno] = []
                self.__kqueue_change_event_map[fileno].append(kevent)
            ''''''

        return

    def poll(self, timeout=0):
        self.__poll_timeout = timeout

        return self.__iowait_func()

    def register(self, fd, eventmask):
        """
        Note:if the event exists,it will not do anything
        """
        is_register = self.__is_register.get(fd, False)

        if is_register: return

        self.__is_register[fd] = True
        self.add_event(fd, eventmask)

    def add_event(self, fd, eventmask):
        """
        Note:if the event exists,it will not do anything
        """
        if not self.__is_register.get(fd, False): return
        is_read = (eventmask & EV_TYPE_READ) == EV_TYPE_READ
        is_write = (eventmask & EV_TYPE_WRITE) == EV_TYPE_WRITE
        if is_read: self.__add_ev_read(fd)
        if is_write: self.__add_ev_write(fd)

    def remove_event(self, fd, eventmask):
        """
        Note:if the event not exists,it will not do anything
        """

        is_read = (eventmask & EV_TYPE_READ) == EV_TYPE_READ
        is_write = (eventmask & EV_TYPE_WRITE) == EV_TYPE_WRITE

        if is_read: self.__del_ev_read(fd)
        if is_write: self.__del_ev_write(fd)

        return

    def set_udata(self, fd, udata):
        """
        get user self-define data
        """
        self.__users_data[fd] = udata

    def unregister(self, fd):
        """
        Note:if the event not exists,it will not do anything
        """
        if fd not in self.__is_register: return
        self.__clean(fd)

    def is_register(self, fd):
        return self.__is_register.get(fd, False)

    def get_udata(self, fd):
        try:
            return self.__users_data[fd]
        except KeyError:
            return -1

    def dbg_get_register_fds(self):
        retlist = [fd for fd in self.__is_register]

        return retlist

    def dbg_print_register_fds(self):
        print(self.dbg_get_register_fds())
