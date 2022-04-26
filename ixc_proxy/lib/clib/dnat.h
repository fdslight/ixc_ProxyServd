#ifndef DNAT_H
#define DNAT_H

#include "mbuf.h"

struct dnat_rule{
    // 要被修改的目标地址
    unsigned char dst_address_old[16];
    // 要修改成的目标地址
    unsigned char dst_address_new[16];
    unsigned char id[16];
    unsigned int refcnt;
};

int dnat_init(void);
void dnat_uninit(void);

int dnat_rule_add(unsigned char *old,unsigned char *_new,unsigned char *user_id,int is_ipv6);
/// 要被修改的地址是否存在
int dnat_rule_old_exists(unsigned char *addr,int is_ipv6);
/// 要修改成的地址是否存在
int dnat_rule_new_exists(unsigned char *addr,int is_ipv6);

/// 通过要被修改的地址删除规则
int dnat_rule_del_by_old(unsigned char *addr,int is_ipv6);
/// 通过要修改成的地址删除规则
int dnat_rule_del_by_new(unsigned char *addr,int is_ipv6);
/// DNAT处理
// 如果匹配那么返回非零值,否则返回零
int dnat_handle(struct mbuf *mbuf,void *ip_header);

/// 开启或者关闭DNAT
int dnat_enable(int enable,int is_ipv6);

#endif