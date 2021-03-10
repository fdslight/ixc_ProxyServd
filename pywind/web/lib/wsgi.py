#!/usr/bin/env python3
import pywind.lib.reader as reader
import pywind.web.lib.httpchunked as httpchunked
import sys, traceback


class wsgi(object):
    __app = None
    __is_finish = False
    __reader = None
    __output_body_func = None
    __output_hdr_func = None
    __finish_func = None

    __resp_status = None
    __resp_headers = None
    __resp_stcode = 0

    __is_resp_hdr = False
    __has_hdr = None
    __is_chunked = False
    __chunked = None

    __resp_content_length = 0
    __responsed_content_length = 0

    __recv_length = 0
    __received_length = 0

    __udata = None
    __debug = None

    def __init__(self, application, cgi_env, output_hdr_func, output_body_func, finish_func, udata=None, debug=False):
        """
        :param application:
        :param caddr: client address
        :param cgi_env: cgi env
        :param output_hdr_func :hdr function
        :param output_body_func: body function
        :param finish_func : finish function
        :param udata:自定义数据
        """
        self.__app = application
        self.__reader = reader.reader()
        self.__output_hdr_func = output_hdr_func
        self.__output_body_func = output_body_func
        self.__finish_func = finish_func
        self.__resp_content_length = 0
        self.__udata = udata
        self.__responsed_content_length = 0
        self.__debug = debug

        wsgi_env = self.__convert2wsgi_env(cgi_env)

        self.__recv_length = int(wsgi_env["CONTENT_LENGTH"])
        try:
            self.__app = application(wsgi_env, self.__start_response)
        except:
            self.__handle_error("500 Internal Server Error", [], traceback.format_exc())
            sys.stderr.write(traceback.format_exc())
        return

    def __convert2wsgi_env(self, cgi_env):
        wsgi_env = cgi_env
        wsgi_env["wsgi.version"] = (1, 0,)
        wsgi_env["wsgi.errors"] = sys.stderr
        wsgi_env["wsgi.multithread"] = False
        wsgi_env['wsgi.multiprocess'] = True
        wsgi_env['wsgi.run_once'] = True
        wsgi_env["wsgi.input"] = self.__reader

        if cgi_env.get('HTTPS', 'off') in ('on', '1'):
            cgi_env['wsgi.url_scheme'] = 'https'
        else:
            cgi_env['wsgi.url_scheme'] = 'http'

        if "PATH_INFO" not in wsgi_env:
            pos = wsgi_env["REQUEST_URI"].find("?")
            if pos < 0:
                wsgi_env["PATH_INFO"] = wsgi_env["REQUEST_URI"]
            else:
                wsgi_env["PATH_INFO"] = wsgi_env["REQUEST_URI"][0:pos]
            ''''''
        return wsgi_env

    def __handle_error(self, status, resp_headers, err_data=""):
        sys.stderr.write(err_data)

        if self.__is_resp_hdr:
            self.__finish_func(udata=self.__udata)
            return

        if self.__debug:
            self.__response_error(status, resp_headers, err_data)
        else:
            self.__response_error(status, resp_headers, "")

    def __response_error(self, status, resp_headers, resp_data=""):
        self.__is_resp_hdr = True
        self.__is_finish = True

        if resp_data:
            resp_data = "%s\r\n\r\n%s" % (status, resp_data,)
            status = "200 OK"

        byte_data = resp_data.encode()
        resp_headers += [("Content-Length", len(byte_data),), ("Content-Type", "text/plain;charset=utf-8",), ]
        self.__output_hdr_func(status, resp_headers, udata=self.__udata)
        self.__output_body_func(byte_data, udata=self.__udata)
        self.__finish_func(udata=self.__udata)

    def __response_body(self, body_data):
        if not self.__is_chunked:
            n = self.__resp_content_length - self.__responsed_content_length
            resp_data = body_data[0:n]

            self.__responsed_content_length += len(resp_data)
            self.__output_body_func(resp_data, udata=self.__udata)
            if self.__resp_content_length == self.__responsed_content_length:
                self.__is_finish = True
            return

        self.__chunked.input(body_data)
        try:
            self.__chunked.parse()
        except httpchunked.ChunkedErr:
            self.__handle_error("500 Internal Server Error", [], traceback.format_exc())
            return

        chunk_data = self.__chunked.get_chunk_with_length()
        if self.__chunked.is_ok(): self.__is_finish = True
        if not chunk_data: return
        self.__output_body_func(chunk_data, udata=self.__udata)

    def finish(self):
        try:
            if hasattr(self.__app, "close"):
                self.__app.close()
        except:
            sys.stderr.write(traceback.format_exc())
            self.__handle_error("500 Internal Server Error", [], traceback.format_exc())

    def input(self, byte_data):
        # 如果响应结束,那么丢弃所有的数据包
        if self.__is_finish: return

        rsize = self.__recv_length - self.__received_length
        byte_data = byte_data[0:rsize]

        self.__recv_length += len(byte_data)
        self.__reader._putvalue(byte_data)

    def handle(self):
        if self.__is_finish:
            if not self.__is_resp_hdr:
                self.__output_hdr_func(self.__resp_status, self.__resp_headers, udata=self.__udata)
                self.__is_resp_hdr = True
            self.__finish_func(udata=self.__udata)
            return
        try:
            for resp_data in self.__app:
                if not self.__has_hdr:
                    continue
                if not self.__is_resp_hdr:
                    self.__output_hdr_func(self.__resp_status, self.__resp_headers, udata=self.__udata)
                    self.__is_resp_hdr = True
                self.__response_body(resp_data)
        except:
            sys.stderr.write(traceback.format_exc())
            self.__handle_error("500 Internal Server Error", [], traceback.format_exc())
            return
        if self.__is_finish:
            self.__finish_func(udata=self.__udata)
        return

    def __start_response(self, status, response_headers, exc_info=None):
        try:
            self.__resp_stcode = int(status[0:3])
        except ValueError:
            self.__handle_error("500 Internal Server Error", [], traceback.format_exc())
            return
        if self.__resp_stcode < 100:
            self.__handle_error("500 Internal Server Error", [], "wrong http status code %s" % self.__resp_stcode)
            return

        if self.__resp_stcode >= 100 and self.__resp_stcode < 200:
            self.__output_hdr_func(status, response_headers, udata=self.__udata)
            return

        if self.__is_resp_hdr:
            self.__handle_error("500 Internal Server Error", [], "http master has responsed!")
            return

        """
        if self.__resp_stcode >= 300:
            self.__output_hdr_func(status, response_headers,udata=self.__udata)
            self.__is_finish = True
            self.__is_resp_hdr = True
            return
        """

        self.__resp_status = status
        self.__resp_headers = response_headers
        self.__has_hdr = True

        for name, value in response_headers:
            name = name.lower()
            if name == "content-length":
                try:
                    self.__resp_content_length = int(value)
                except ValueError:
                    self.__response_error("500 Internal Server Error", [], traceback.format_exc())
                    return
                break
            if name == "transfer-encoding" and value.lower() == "chunked":
                self.__is_chunked = True
                self.__chunked = httpchunked.parser()
                break
        if self.__is_chunked: return
        if self.__resp_content_length == 0: self.__is_finish = True
