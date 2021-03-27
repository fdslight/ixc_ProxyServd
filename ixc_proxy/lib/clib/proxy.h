#ifndef PROXY_H
#define PROXY_H

#include "mbuf.h"

/// 发送网络数据包
int netpkt_send(struct mbuf *m);

/// 接收UDP数据包
int netpkt_udp_recv(unsigned char *id,unsigned char *saddr,unsigned char *daddr,unsigned short sport,unsigned short dport,int is_udplite,int is_ipv6,void *data,int size);

/// TCP连接事件
int netpkt_tcp_conn_ev(unsigned char *uid,unsigned char *session_id,unsigned char *saddr,unsigned char *daddr,unsigned short sport,unsigned short dport,int is_ipv6);

/// TCP数据接收
int netpkt_tcp_recv(unsigned char *uid,unsigned char *session_id,int win_size,void *data,unsigned short payload_len,int is_ipv6);

/// 关闭TCP连接
int netpkt_tcp_close_ev(unsigned char *uid,unsigned char *session_id,int is_ipv6);


#endif