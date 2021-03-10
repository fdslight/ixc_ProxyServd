#include<string.h>
#include<stdlib.h>

#include "ipalloc.h"
#include "debug.h"

#include "../../../pywind/clib/netutils.h"

static struct ipalloc ipalloc;
static int ipalloc_is_initialized=0;

/// 对指定的IP地址加1
static int ipalloc_addr_plus(unsigned char *address,int is_ipv6,unsigned char *result)
{
    int count=is_ipv6?15:3;
    // flags代表是否产生进位
    unsigned char v,flags=0;
    int rs=-1;

    if(is_ipv6) memcpy(result,address,16);
    else memcpy(result,address,4);

    for(int x=count;x>=0;x--){
        v=result[x];
        if(v==0xff){
            flags=1;
            result[x]=0;
        }else{
            result[x]=result[x]+flags;
            rs=0;
            break;
        }
    }

    return rs;
}

int ipalloc_init(void)
{
    bzero(&ipalloc,sizeof(struct ipalloc));
    ipalloc_is_initialized=1;

    return 0;
}

void ipalloc_uninit(void)
{
    struct ipalloc_record *r=ipalloc.empty_ip6_head,*t;
    while(NULL!=r){
        t=r->next;
        free(r);
        r=t;
    }
    r=ipalloc.empty_ip_head;
    while(NULL!=r){
        t=r->next;
        free(r);
        r=t;
    }
    ipalloc_is_initialized=0;
}

struct ipalloc_record *ipalloc_alloc(int is_ipv6)
{
    struct ipalloc_record *r=NULL;
    unsigned char result[16];
    unsigned char subnet[16];
    unsigned char *addr_ptr=is_ipv6?ipalloc.ip6_cur:ipalloc.ip_cur;
    unsigned char *msk_ptr=is_ipv6?ipalloc.ip6_mask:ipalloc.ip_mask;

    if(is_ipv6 && !ipalloc.isset_ip6_subnet){
        STDERR("no set IPv6 subnet\r\n");
        return NULL;
    }

    if(!is_ipv6 && !ipalloc.isset_ip_subnet){
        STDERR("no set IP subnet\r\n");
        return NULL;
    }

    int rs=ipalloc_addr_plus(addr_ptr,is_ipv6,result);
    //DBG_FLAGS;
    if(rs<0) return NULL;
    //DBG_FLAGS;
    
    // 检查IP地址是否还是属于当前的子网
    subnet_calc_with_msk(addr_ptr,msk_ptr,is_ipv6,subnet);
    if(is_ipv6){
        if(memcmp(subnet,ipalloc.ip6_subnet,16)){
            //DBG_FLAGS;
            return NULL;
        }
    }else{
        if(memcmp(subnet,ipalloc.ip_subnet,4)){
            //PRINT_IP(" ",subnet);
            //PRINT_IP("subnet ",ipalloc.ip6_subnet);
            //DBG_FLAGS;
            return NULL;
        }
    }

    //DBG_FLAGS;
    r=malloc(sizeof(struct ipalloc_record));
    if(NULL==r){
        STDERR("no memory for malloc struct ipalloc_record\r\n");
        return NULL;
    }

    r->next=NULL;
    if(is_ipv6){
        memcpy(r->address,result,16);
        memcpy(addr_ptr,result,16);

        PRINT_IP6("alloc IPv6 address ",result);
    }else{
        memcpy(r->address,result,4);
        memcpy(addr_ptr,result,4);

        PRINT_IP("alloc IP address ",result);
    }

    return r;
}

void ipalloc_free(struct ipalloc_record *record,int is_ipv6)
{
    if(ipalloc.free_record_num==IPALLOC_FREE_NUM){
        free(record);
        return;
    }

    if(is_ipv6){
        record->next=ipalloc.empty_ip6_head;
        ipalloc.empty_ip6_head=record;
    }else{
        record->next=ipalloc.empty_ip_head;
        ipalloc.empty_ip_head=record;
    }
}

int ipalloc_subnet_set(unsigned char *subnet,unsigned char prefix,int is_ipv6)
{
    unsigned char mask[16];

    if(is_ipv6 && ipalloc.isset_ip6_subnet){
        STDERR("there have set IPv6 subnet\r\n");
        return -1;
    }

    if(!is_ipv6 && ipalloc.isset_ip_subnet){
        STDERR("there have set IP subnet\r\n");
        return -1;
    }

    msk_calc(prefix,is_ipv6,mask);
    
    if(is_ipv6){
        memcpy(ipalloc.ip6_subnet,subnet,16);
        memcpy(ipalloc.ip6_mask,mask,16);

        ipalloc.isset_ip6_subnet=1;
    }else{
        memcpy(ipalloc.ip_subnet,subnet,4);

        PRINT_IP(" ",ipalloc.ip_subnet);
        memcpy(ipalloc.ip_mask,mask,4);

        ipalloc.isset_ip_subnet=1;
    }

    return 0;
}