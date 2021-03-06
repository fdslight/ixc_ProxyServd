
#include<string.h>

#include "debug.h"
#include "static_nat.h"

#include "../../../pywind/clib/timer.h"

static struct static_nat static_nat;
static int static_nat_is_initialized=0;
static struct time_wheel static_nat_time_wheel;



static void static_nat_handle_v4(struct mbuf *m)
{
    struct netutil_iphdr *header=(struct netutil_iphdr *)(m->data+m->offset);

    
}


static void static_nat_handle_v6(struct mbuf *m)
{
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);


}

int static_nat_init(void)
{
    bzero(&static_nat,sizeof(struct static_nat));



    static_nat_is_initialized=1;
    return 0;
}

void static_nat_uninit(void)
{

}

void static_nat_handle(struct mbuf *m)
{
    if(m->is_ipv6) static_nat_handle_v6(m);
    else static_nat_handle_v4(m);
}

void static_nat_ip_subnet_set(unsigned char *subnet,unsigned char prefix,int is_ipv6)
{

}