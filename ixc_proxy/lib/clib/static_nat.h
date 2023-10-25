#ifndef STATIC_NAT_H
#define STATIC_NAT_H

#include<sys/types.h>

#include "mbuf.h"
#include "ipalloc.h"

#include "../../../pywind/clib/map.h"
#include "../../../pywind/clib/timer.h"

#define STATIC_NAT_TIMEOUT 180

struct static_nat_record{
    struct time_data *tdata;
    struct ipalloc_record *ip_record;
    unsigned char id[16];
    unsigned char lan_addr1[16];
    unsigned char lan_addr2[16];
    time_t up_time;
    // 引用次数
    unsigned int refcnt;
    int is_ipv6;
};

struct static_nat{
    struct map *natv4_lan2wan;
    struct map *natv4_wan2lan;
    
    struct map *natv6_lan2wan;
    struct map *natv6_wan2lan;
};

int static_nat_init(void);
void static_nat_uninit(void);

void static_nat_handle(struct mbuf *m);

int static_nat_bind(unsigned char *id,unsigned char *address,int is_ipv6);

/// 修改TCP MSS
int static_nat_modify_tcp_mss(unsigned int mss,int is_ipv6);

#endif