#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.wsgi as wsgi
import socket, os, time


class scgiErr(Exception): pass


class scgid_listener(tcp_handler.tcp_handler):
    # 最大连接数
    __max_conns = 0
    __current_conns = 0
    __configs = None
    __wsgi = None

    def init_func(self, creator_fd, configs):
        self.__configs = configs
        self.__max_conns = configs.get("max_conns", 100)
        use_unix_socket = configs.get("use_unix_socket", False)
        if use_unix_socket:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            s = socket.socket()
        listen = configs.get("listen", ("127.0.0.1", 8000,))

        if use_unix_socket and os.path.exists(listen): os.remove(listen)

        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.set_socket(s)
        self.bind(listen)
        return self.fileno

    def after(self):
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            if self.__current_conns == self.__max_conns:
                cs.close()
                continue
            self.create_handler(self.fileno, scgid, cs, caddr, self.__configs)
            self.__current_conns += 1

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd != "close_conn": return
        self.__current_conns -= 1

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class scgid(tcp_handler.tcp_handler):
    __creator = -1
    __application = None
    __timeout = 0
    __header_ok = False
    __wsgi = None
    __mtime = None
    __sent_buf = None
    __closed = None
    __configs = None

    def __parse_scgi_header(self):
        size = self.reader.size()
        rdata = self.reader.read()
        rdata_bak = rdata
        pos = rdata.find(b":")

        if pos < 0 and size > 16: raise scgiErr("cannot found length")
        try:
            tot_len = int(rdata[0:pos])
        except ValueError:
            raise scgiErr("invalid length character")

        pos += 1
        rdata = rdata[pos:]

        if rdata[0:14] != b"CONTENT_LENGTH": raise scgiErr("cannot found content_length at first")

        t = rdata[15:]
        pos = t.find(b"\0")

        if pos < 0: raise scgiErr("cannot found content_length border")

        try:
            content_length = int(t[0:pos])
        except ValueError:
            raise scgiErr("invalid content_length character")

        hdr_size = tot_len - content_length + 1
        hdr_data = rdata[0:hdr_size]

        if len(hdr_data) != hdr_size:
            self.reader._putvalue(rdata_bak)
            return (False, None, None,)

        hdr_data = rdata[pos:hdr_size]
        sts = hdr_data.decode("iso-8859-1")

        if sts[-1] != ",": raise scgiErr("wrong scgi header end")

        sts = sts[0:-2]
        tmplist = sts.split("\0")
        Lsize = len(tmplist)

        if Lsize % 2 != 0:
            raise scgiErr("wrong scgi request")

        cgi_env = {}
        a, b = (0, 1,)

        while b < Lsize:
            name = tmplist[a]
            value = tmplist[b]
            cgi_env[name] = value
            a = a + 2
            b = b + 2

        cgi_env["CONTENT_LENGTH"] = content_length

        return (True, cgi_env, rdata[hdr_size:],)

    def init_func(self, creator_fd, cs, caddr, configs):
        self.__creator = creator_fd
        self.__configs = configs
        self.__application = configs.get("application", None)
        self.__timeout = configs.get("timeout", 30)
        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.__mtime = time.time()
        self.__sent_buf = []
        self.__closed = False

        return self.fileno

    def tcp_readable(self):
        if self.__header_ok:
            self.__wsgi.input(self.reader.read())
            return
        ok, cgi_env, body_data = self.__parse_scgi_header()
        if not ok: return
        self.__header_ok = True

        del cgi_env["SCGI"]

        self.__wsgi = wsgi.wsgi(self.__application, cgi_env, self.__resp_header, self.__resp_body_data,
                                self.__finish_request, debug=self.__configs.get("debug", False))
        self.__wsgi.input(body_data)
        self.__mtime = time.time()
        self.__wsgi.handle()
        self.add_to_loop_task(self.fileno)

    def tcp_writable(self):
        self.__mtime = time.time()
        if self.__sent_buf: self.writer.write(self.__sent_buf.pop(0))
        if self.writer.size() == 0:
            self.remove_evt_write(self.fileno)
            return

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        t = time.time()

        if self.__mtime + self.__timeout < t:
            self.delete_handler(self.fileno)
            return

        self.set_timeout(self.fileno, self.__timeout)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()
        self.ctl_handler(self.fileno, self.__creator, "close_conn")

        if self.__wsgi: self.__wsgi.finish()

    def task_loop(self):
        if self.__closed and not self.__sent_buf and self.writer.size() == 0:
            self.delete_handler(self.fileno)
            return
        self.__wsgi.handle()

    def __finish_request(self, *args, **kwargs):
        self.__closed = True

    def __resp_body_data(self, body_data, *args, **kwargs):
        self.add_evt_write(self.fileno)
        self.__sent_buf += self.slice_data(body_data)

    def __resp_header(self, status, resp_headers, *args, **kwargs):
        tmplist = ["Status: %s\r\n" % status, ]

        for name, value in resp_headers:
            sts = "%s: %s\r\n" % (name, value,)
            tmplist.append(sts)
        tmplist.append("\r\n")

        self.add_evt_write(self.fileno)

        byte_data = "".join(tmplist).encode()
        self.__sent_buf += self.slice_data(byte_data)

    def slice_data(self, byte_data, block_size=4096):
        """对数据进行分片
        """
        b, e = (0, block_size,)
        results = []

        while 1:
            data = byte_data[b:e]
            if not data: break
            b = e
            e += block_size
            results.append(data)

        return results
