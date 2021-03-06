#ifndef IPALLOC_H
#define IPALLOC_H

struct ipalloc_record{
    struct ipalloc_record *next;
    unsigned char address[16];
};

struct ipalloc{
    // 空的IPv6地址列表
    struct ipalloc_record *empty_ip6_head;
    // 空的IP地址列表
    struct ipalloc_record *empty_ip_head;
    // 当前的IPv6地址
    unsigned char ip6_cur[16];
    unsigned char ip6_subnet[16];
    unsigned char ip6_mask[16];

    // 当前的IP地址
    unsigned char ip_cur[4];
    unsigned char ip_subnet[4];
    unsigned char ip_mask[4];
    // 是否已经设置了IP子网
    int isset_ip_subnet;
    // 是否已经设置了IPv6子网
    int isset_ip6_subnet;
};

int ipalloc_init(void);
void ipalloc_uninit(void);

/// 获取空闲的IP地址
struct ipalloc_record *ipalloc_alloc(int is_ipv6);
/// 释放IP地址
void ipalloc_free(struct ipalloc_record *record,int is_ipv6);
/// 子网设置
int ipalloc_subnet_set(unsigned char *subnet,unsigned char prefix,int is_ipv6);

#endif