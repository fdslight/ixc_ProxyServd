#ifndef STATIC_NAT_H
#define STATIC_NAT_H

#include "mbuf.h"

#include "../../../pywind/clib/map.h"

struct static_nat_record{
    unsigned char lan_addr[16];
    unsigned char wan_addr[16];
    // 引用次数
    unsigned int refcnt;
    int is_ipv6;
};

struct static_nat{
    struct map *natv4;
    struct map *natv6;
};

int static_nat_init(void);
void static_nat_uninit(void);

void static_nat_handle(struct mbuf *m);

#endif