#ifndef IXC_IPv6_H
#define IXC_IPv6_H

#include "mbuf.h"

void ipv6_handle(struct mbuf *m);

int ipv6_send(unsigned char *src_addr,unsigned char *dst_addr,unsigned char protocol,void *data,unsigned short length);
int ipv6_mtu_set(unsigned short mtu);

#endif