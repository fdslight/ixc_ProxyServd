#include<string.h>
#include<stdlib.h>

#include "ipalloc.h"
#include "debug.h"

#include "../../../pywind/clib/netutils.h"

static struct ipalloc ipalloc;
static int ipalloc_is_initialized=0;

int ipalloc_init(void)
{
    bzero(&ipalloc,sizeof(struct ipalloc));
    ipalloc_is_initialized=1;
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
    return NULL;
}

void ipalloc_free(struct ipalloc_record *record,int is_ipv6)
{
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
        memcpy(ipalloc.ip_mask,subnet,4);

        ipalloc.isset_ip_subnet=1;
    }

}