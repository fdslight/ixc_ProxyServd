#include<stdlib.h>
#include<string.h>

#include "debug.h"
#include "dnat.h"
#include "proxy.h"

#include "../../../pywind/clib/map.h"
#include "../../../pywind/clib/netutils.h"

/// 方向为TUNDEV到ixcsys客户端
static struct map *dnat_old2new_ip=NULL;
static struct map *dnat_new2old_ip=NULL;

static struct map *dnat_old2new_ip6=NULL;
static struct map *dnat_new2old_ip6=NULL;

static int dnat_ip_enable=0;
static int dnat_ip6_enable=0;

void dnat_rule_del_cb(void *r)
{
    struct dnat_rule *rule=r;
    
    rule->refcnt-=1;
    if(rule->refcnt==0) free(rule);
}

int dnat_init(void)
{
    int rs;

    dnat_old2new_ip=NULL;
    dnat_new2old_ip=NULL;

    dnat_old2new_ip6=NULL;
    dnat_new2old_ip6=NULL;

    dnat_ip_enable=0;
    dnat_ip6_enable=0;

    rs=map_new(&dnat_old2new_ip,4);
    if(rs!=0){
        dnat_uninit();
        STDERR("cannot create map old2new\r\n");
        return -1;
    }
    rs=map_new(&dnat_new2old_ip,4);
    if(rs!=0){
        dnat_uninit();
        STDERR("cannot create map new2old\r\n");
        return -1;
    }
    rs=map_new(&dnat_old2new_ip6,16);
    if(rs!=0){
        dnat_uninit();
        STDERR("cannot create map old2new ipv6\r\n");
        return -1;
    }
    rs=map_new(&dnat_new2old_ip6,16);
    if(rs!=0){
        dnat_uninit();
        STDERR("cannot create map new2old ipv6\r\n");
        return -1;
    }

    return 0;
}

void dnat_uninit(void)
{
    if(NULL!=dnat_old2new_ip) map_release(dnat_old2new_ip,dnat_rule_del_cb);
    if(NULL!=dnat_new2old_ip) map_release(dnat_new2old_ip,dnat_rule_del_cb);
    if(NULL!=dnat_old2new_ip6) map_release(dnat_old2new_ip6,dnat_rule_del_cb);
    if(NULL!=dnat_new2old_ip6) map_release(dnat_new2old_ip6,dnat_rule_del_cb);
}

int dnat_rule_add(unsigned char *old,unsigned char *_new,unsigned char *user_id,int is_ipv6)
{
    char is_found;
    int rs;
    struct map *m_old=is_ipv6?dnat_old2new_ip6:dnat_old2new_ip;
    struct map *m_new=is_ipv6?dnat_new2old_ip6:dnat_new2old_ip;

    struct dnat_rule *r=map_find(m_old,(char *)old,&is_found);
    if(NULL!=r){
        STDERR("rule exists\r\n");
        return -1;
    }
    r=malloc(sizeof(struct dnat_rule));
    if(NULL==r){
        STDERR("no memory for struct dnat_rule\r\n");
        return -1;
    }
    rs=map_add(m_old,(char *)old,r);
    if(0!=rs){
        free(r);
        STDERR("cannot add to dnat\r\n");
        return -1;
    }
    rs=map_add(m_new,(char *)_new,r);
    if(0!=rs){
        map_del(m_old,(char *)old,NULL);
        free(r);
        STDERR("cannot add to dnat\r\n");
        return -1;
    }

    if(is_ipv6) {
        memcpy(r->dst_address_old,old,16);
        memcpy(r->dst_address_new,_new,16);
    }else{
        memcpy(r->dst_address_old,old,4);
        memcpy(r->dst_address_new,_new,4);
    }
    memcpy(r->id,user_id,16);
    r->refcnt=2;

    return 0;
}

int dnat_rule_old_exists(unsigned char *addr,int is_ipv6)
{
    struct map *m_old=is_ipv6?dnat_old2new_ip6:dnat_old2new_ip;
    char is_found;

    map_find(m_old,(char *)addr,&is_found);

    return is_found;
}

int dnat_rule_new_exists(unsigned char *addr,int is_ipv6)
{
    struct map *m_new=is_ipv6?dnat_new2old_ip6:dnat_new2old_ip;
    char is_found;
    
    map_find(m_new,(char *)addr,&is_found);

    return is_found;
}

int dnat_rule_del_by_old(unsigned char *addr,int is_ipv6)
{
    struct map *m_old=is_ipv6?dnat_old2new_ip6:dnat_old2new_ip;
    struct map *m_new=is_ipv6?dnat_new2old_ip6:dnat_new2old_ip;
    char is_found;
    struct dnat_rule *r=map_find(m_old,(char *)addr,&is_found); 

    if(NULL==r) return -1;

    map_del(m_old,(char *)addr,dnat_rule_del_cb);
    map_del(m_new,(char *)(r->dst_address_new),dnat_rule_del_cb);

    return 0;
}

int dnat_rule_del_by_new(unsigned char *addr,int is_ipv6)
{
    struct map *m_old=is_ipv6?dnat_old2new_ip6:dnat_old2new_ip;
    struct map *m_new=is_ipv6?dnat_new2old_ip6:dnat_new2old_ip;
    char is_found;
    struct dnat_rule *r=map_find(m_new,(char *)addr,&is_found); 

    if(NULL==r) return -1;

    map_del(m_old,(char *)(r->dst_address_old),dnat_rule_del_cb);
    map_del(m_new,(char *)addr,dnat_rule_del_cb);

    return 0;
}

int dnat_handle(struct mbuf *mbuf,void *ip_header)
{
    struct dnat_rule *rule=NULL;
    struct map *m;
    char is_found;
    unsigned char *addr;
    struct netutil_ip6hdr *ip6hdr=NULL;
    struct netutil_iphdr *iphdr=NULL;

    STDOUT("DNAT enable %d\r\n",dnat_ip_enable);

    if(mbuf->is_ipv6 && !dnat_ip6_enable) return 0;
    if(!mbuf->is_ipv6 && !dnat_ip_enable) return 0;

    DBG_FLAGS;
    if(mbuf->is_ipv6) {
        ip6hdr=ip_header;
        if(mbuf->from==MBUF_FROM_LAN){
            m=dnat_new2old_ip6;
            addr=ip6hdr->src_addr;
        }else{
            m=dnat_old2new_ip6;
            addr=ip6hdr->dst_addr;
        }
    }
    else{
        iphdr=ip_header;
        if(mbuf->from==MBUF_FROM_LAN){
            m=dnat_new2old_ip;
            addr=iphdr->src_addr;
        }else{
            m=dnat_old2new_ip;
            addr=iphdr->dst_addr;
        }
    }

    if(mbuf->is_ipv6){
        PRINT_IP6("PRINT IPv6",addr);
    }else{
        PRINT_IP("PRINT IP",addr);
    }
    rule=map_find(m,(char *)addr,&is_found);
    DBG_FLAGS;

    // 未找到规则的处理方式
    if(NULL==rule) return 0;

    if(mbuf->from==MBUF_FROM_LAN){
        if(mbuf->is_ipv6) rewrite_ip6_addr(ip6hdr,rule->dst_address_old,1);
        else rewrite_ip_addr(iphdr,rule->dst_address_old,1);
    }else{
        if(mbuf->is_ipv6) rewrite_ip6_addr(ip6hdr,rule->dst_address_new,0);
        else rewrite_ip_addr(iphdr,rule->dst_address_new,0);
    }

    memcpy(mbuf->id,rule->id,16);
    netpkt_send(mbuf);

    return 1;
}

int dnat_enable(int enable,int is_ipv6)
{
    if(is_ipv6) dnat_ip6_enable=enable;
    else dnat_ip_enable=enable;
    
    return 0;
}