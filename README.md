IP代理软件服务端for ixcsys

# 软件配置(在ixc_configs目录下)
config.ini 里的nat中eth_name必须要改成实际机器网口名，其他请根据需求根据注释更改

# 日志路径
/tmp目录下以ixc_开头的文件


# 运行环境(Linux)
python3并且需要安装cryptography模块

# ubuntu/debian安装环境配置
sudo apt install python3-pip  
sudo pip3 install cryptography

# 软件编译
python3 ixc_install.py ${python3_include_path}

${python3_include_path}:python3头文件路径，比如/usr/include/python3.9

# 服务端启动
sudo python3 ixc_server.py -d start

# 中继服务端启动(例子)
python3 ixc_relay.py --bind=0.0.0.0,8080 --redirect=www.example.com,8443 -p tcp

# 停止
sudo python3 ixc_server.py -d stop
