#ifndef IP2SOCKS_UDP_H
#define IP2SOCKS_UDP_H

#include "mbuf.h"

void udp_handle(struct mbuf *m,int is_ipv6);
/// 发送UDP数据,如果非UDPLite,参数csum_coverage将被忽略
int udp_send(unsigned char *saddr,unsigned char *daddr,unsigned short sport,unsigned short dport,int is_udplite,int is_ipv6,unsigned short csum_coverage,void *data,size_t length);

#endif