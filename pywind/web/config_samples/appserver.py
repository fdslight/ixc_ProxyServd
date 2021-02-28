#!/usr/bin/env python3
configs = {
    "process": 1,  # 进程数目
    "max_conns": 10,  # 最大连接数
    "listen": ("127.0.0.1", 8000,),  # 监听地址
    "application": None,
    "use_unix_socket": False,
}
