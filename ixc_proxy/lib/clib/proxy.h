#ifndef PROXY_H
#define PROXY_H

#include "mbuf.h"

/// 发送网络数据包
int netpkt_send(struct mbuf *m);

/// 接收UDP数据包
int netpkt_udp_recv(unsigned char *id,unsigned char *saddr,unsigned char *daddr,unsigned short sport,unsigned short dport,int is_udplite,int is_ipv6,void *data,int size);


#endif