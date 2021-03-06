#ifndef STATIC_NAT_H
#define STATIC_NAT_H

#include<sys/types.h>

#include "mbuf.h"
#include "ipalloc.h"

#include "../../../pywind/clib/map.h"
#include "../../../pywind/clib/timer.h"

#define STATIC_NAT_TIMEOUT 900

struct static_nat_record{
    struct time_data *tdata;
    struct ipalloc_record *ip_record;
    unsigned char lan_addr1[16];
    unsigned char lan_addr2[16];
    time_t up_time;
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