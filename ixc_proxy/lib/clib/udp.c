
#include<sys/types.h>
#include<arpa/inet.h>
#include<string.h>

#include "udp.h"
#include "debug.h"
#include "mbuf.h"
#include "ip.h"
#include "ipv6.h"

#include "ip2socks.h"

#include "../../../pywind/clib/netutils.h"

static void __udp_handle_v4(struct mbuf *m)
{
    struct netutil_iphdr *header=(struct netutil_iphdr *)(m->data+m->offset);
    struct netutil_udphdr *udphdr=NULL;

    unsigned char protocol=header->protocol;
    int hdr_len=(header->ver_and_ihl & 0x0f) * 4,is_udplite;
    unsigned char saddr[4],daddr[4];
    unsigned short sport,dport;

    memcpy(saddr,header->src_addr,4);
    memcpy(daddr,header->dst_addr,4);

    m->offset+=hdr_len;
    udphdr=(struct netutil_udphdr *)(m->data+m->offset);

    is_udplite=protocol==17?0:1;

    sport=ntohs(udphdr->src_port);
    dport=ntohs(udphdr->dst_port);

    netpkt_udp_recv(saddr,daddr,sport,dport,is_udplite,0,m->data+m->offset+8,m->tail-m->offset-8);
    mbuf_put(m);
}

static void __udp_handle_v6(struct mbuf *m)
{
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);
    struct netutil_udphdr *udphdr=NULL;
    unsigned char next_header=header->next_header;
    unsigned char saddr[16],daddr[16];
    unsigned short sport,dport;
    int is_udplite;

    memcpy(saddr,header->src_addr,16);
    memcpy(daddr,header->dst_addr,16);

    m->offset+=40;
    is_udplite=next_header==17?0:1;

    udphdr=(struct netutil_udphdr *)(m->data+m->offset);

    sport=ntohs(udphdr->src_port);
    dport=ntohs(udphdr->dst_port);

    netpkt_udp_recv(saddr,daddr,sport,dport,is_udplite,1,m->data+m->offset+8,m->tail-m->offset-8);
    
    mbuf_put(m);
}

void udp_handle(struct mbuf *m,int is_ipv6)
{
    if(is_ipv6) __udp_handle_v6(m);
    else __udp_handle_v4(m);
}

int udp_send(unsigned char *saddr,unsigned char *daddr,unsigned short sport,unsigned short dport,int is_udplite,int is_ipv6,unsigned short csum_coverage,void *data,size_t length)
{
    struct netutil_udphdr *udphdr;
    struct netutil_ip6_ps_header *ps6_header;
    struct netutil_ip_ps_header *ps_header;
    struct mbuf *m=NULL;
    unsigned char p;
    unsigned short csum;
    int offset;
    
    p=is_udplite?136:17;

    if(is_udplite && csum_coverage<8){
        STDERR("wrong udplite csum_coverage value\r\n");
        return -1;
    }

    m=mbuf_get();
    if(NULL==m){
        STDERR("cannot get mbuf\r\n");
        return -1;
    }

    m->begin=MBUF_BEGIN;
    m->offset=m->begin;
    m->tail=m->begin+length+8;
    m->end=m->tail;

    udphdr=(struct netutil_udphdr *)(m->data+m->offset);
    bzero(udphdr,sizeof(struct netutil_udphdr));

    udphdr->src_port=htons(sport);
    udphdr->dst_port=htons(dport);

    if(is_udplite) udphdr->csum_coverage=htons(csum_coverage);
    else udphdr->length=htons(length+8);

    if(is_ipv6){
        offset=m->begin-40;
        ps6_header=(struct netutil_ip6_ps_header *)(m->data+offset);

        bzero(ps6_header,40);

        memcpy(ps6_header->src_addr,saddr,16);
        memcpy(ps6_header->dst_addr,daddr,16);

        ps6_header->next_header=p;
        ps6_header->length=htons(length+8);
    }else{
        offset=m->begin-12;
        ps_header=(struct netutil_ip_ps_header *)(m->data+offset);

        bzero(ps_header,12);

        memcpy(ps_header->src_addr,saddr,4);
        memcpy(ps_header->dst_addr,daddr,4);

        ps_header->protocol=p;
        ps_header->length=htons(length+8);
    }


    memcpy(m->data+m->offset+8,data,length);

    if(is_udplite) csum=csum_calc((unsigned short *)(m->data+m->offset),csum_coverage);
    else csum=csum_calc((unsigned short *)(m->data+offset),m->end-offset);
    
    udphdr->checksum=csum;
    
    if(is_ipv6) ipv6_send(saddr,daddr,p,m->data+m->begin,m->end-m->begin);
    else ip_send(saddr,daddr,p,m->data+m->begin,m->end-m->begin);

    mbuf_put(m);

    return 0;
}