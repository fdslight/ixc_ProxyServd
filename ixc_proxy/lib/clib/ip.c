#include<arpa/inet.h>
#include<string.h>
#include<time.h>
#include<stdlib.h>

#include "ip.h"
#include "ipv6.h"
#include "ipunfrag.h"
#include "ip2socks.h"
#include "udp.h"
#include "tcp.h"

#include "../../../pywind/clib/debug.h"
#include "../../../pywind/clib/netutils.h"

static int ip_mtu=1400;

void ip_handle(struct mbuf *m)
{
    struct netutil_iphdr *header=(struct netutil_iphdr *)(m->data+m->offset);
    int version= (header->ver_and_ihl & 0xf0) >> 4;
    int is_supported=0;
    unsigned short frag_info,frag_off;
    int mf;
    
    // 检查是否是IPv6,如果是IPv6那么处理IPv6协议
    if(version==6){
        ipv6_handle(m);
        return;
    }

    switch(header->protocol){
        case 6:
        case 17:
        case 136:
            is_supported=1;
            break;
        default:
            break;
    }

    if(!is_supported){
        mbuf_put(m);
        return;
    }

    frag_info=ntohs(header->frag_info);
    frag_off=frag_info & 0x1fff;
    mf=frag_info & 0x2000;
    
    // 如果IP数据包有分包那么首先合并数据包
    if(mf!=0 || frag_off!=0) m=ipunfrag_add(m);
    if(NULL==m) return;
    
    switch(header->protocol){
        // 处理TCP协议
        case 6:
            tcp_handle(m,0);
            break;
        // 处理UDP和UDPLite协议
        case 17:
        case 136:
            udp_handle(m,0);
            break;
    }
}

int ip_send(unsigned char *src_addr,unsigned char *dst_addr,unsigned char protocol,void *data,unsigned short length)
{
    struct netutil_iphdr *header;
    unsigned short id=0,slice=ip_mtu-20,cur_slice_size=0,csum=0;
    unsigned char *ptr=data;
    struct mbuf *m=NULL;
    int tot_size=0,rs=0;
    unsigned short df=0x4000,mf=0x0000,frag_off=0;

    srand(time(NULL));

    id=htons(rand() & 0xffff);

    while(tot_size<length){
        m=mbuf_get();
        if(NULL==m){
            rs=-1;
            STDERR("cannot get mbuf\r\n");
            break;
        }

        if(length-tot_size <= slice){
            cur_slice_size=length-tot_size;
            mf=0x0000;
        }else{
            // 此处需要为8的倍数
            cur_slice_size=(slice/8*8);
            mf=0x2000;
        }
        
        m->begin=m->offset=MBUF_BEGIN;
        m->end=m->tail=m->begin+length+20;

        header=(struct netutil_iphdr *)(m->data+m->begin);
        bzero(header,20);

        header->ver_and_ihl=0x45;
        header->tos=0x01;
        header->ttl=0x40;
        header->id=id;
        header->frag_info=htons(df | mf | frag_off);
        header->tot_len=htons(20+cur_slice_size);
        header->protocol=protocol;

        memcpy(header->src_addr,src_addr,4);
        memcpy(header->dst_addr,dst_addr,4);

        csum=csum_calc((unsigned short *)header,20);
        header->checksum=csum;

        memcpy(m->data+m->begin+20,ptr+tot_size,cur_slice_size);

        tot_size+=cur_slice_size;
        frag_off+=(cur_slice_size/8);

        netpkt_send(m,protocol,0);
    }
    
    return rs;
}

int ip_mtu_set(unsigned short mtu)
{
    ip_mtu=mtu;
    return 0;
}