#ifndef IP2SOCKS_IP_H
#define IP2SOCKS_IP_H

#include "mbuf.h"

void ip_handle(struct mbuf *m);

int ip_send(unsigned char *src_addr,unsigned char *dst_addr,unsigned char protocol,void *data,unsigned short length);
int ip_mtu_set(unsigned short mtu);

#endif