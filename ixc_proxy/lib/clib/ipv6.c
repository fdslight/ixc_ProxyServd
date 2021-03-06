#include<string.h>

#include "ipv6.h"
#include "ip6unfrag.h"
#include "tcp.h"
#include "udp.h"
#include "ip2socks.h"

#include "../../../pywind/clib/debug.h"
#include "../../../pywind/clib/netutils.h"

static int ipv6_mtu=1280;

void ipv6_handle(struct mbuf *m)
{
    struct netutil_ip6hdr *header;

    m=ip6unfrag_add(m);
    if(NULL==m) return;

    header=(struct netutil_ip6hdr *)(m->data+m->offset);

    switch(header->next_header){
        case 6:
            tcp_handle(m,1);
            break;
        case 17:
            udp_handle(m,1);
            break;
        default:
            mbuf_put(m);
            break;
    }
}

int ipv6_send(unsigned char *src_addr,unsigned char *dst_addr,unsigned char protocol,void *data,unsigned short length)
{
    struct netutil_ip6hdr *header=NULL;
    struct netutil_ip6_frag_header *frag_header=NULL;
    struct mbuf *m;
    // 能够传输的最大数据
    int payload_max=ipv6_mtu-40;
    // 数据分片大小
    int slice_size=payload_max/8*8;
    // 当前已经传送的数据大小
    int cur_payload=0;
    int rs=0;
    int data_size;
    int header_size;
    // 是否需要分片
    int need_slice;
    char *data_ptr=data;
    unsigned short offset=0,frag_off=0,M;
    unsigned int id=0;

    data_size=length-cur_payload;
    if(data_size>payload_max){
        data_size=slice_size;
        need_slice=1;
        srand(time(NULL));
        id=htonl(rand() & 0xffffffff);
        header_size=48;
    }else {
        header_size=40;
        need_slice=0;
    }

    while(cur_payload<length){
        m=mbuf_get();
 
        if(NULL==m){
            rs=-1;
            STDERR("cannot get mbuf for ipv6\r\n");
            break;
        }

        m->begin=m->offset=MBUF_BEGIN;
        
        bzero(m->data+m->offset,header_size);
        bzero(m->data+m->offset,200);
        
        header=(struct netutil_ip6hdr *)(m->data+m->offset);

        header->ver_and_tc=0x60;
        header->hop_limit=0x40;

        memcpy(header->src_addr,src_addr,16);
        memcpy(header->dst_addr,dst_addr,16);

        // 处理需要分片的情况
        if(need_slice){
            header->next_header=44;
            
            if(cur_payload+data_size-8>=length){
                M=0x0000;
                data_size=length-cur_payload+8;
            }else{
                M=0x0001;
            }

            m->end=m->tail=MBUF_BEGIN+data_size+40;

            memcpy(m->data+m->offset+header_size,data_ptr,data_size-8);

            frag_header=(struct netutil_ip6_frag_header *)(m->data+m->offset+40);
            
            frag_off= (offset << 3 | M);
            frag_off=htons(frag_off);
            frag_header->frag_off=frag_off;
            frag_header->id=id;
            frag_header->next_header=protocol;

            cur_payload=cur_payload+data_size-8;
            offset=offset+(data_size-8)/8;

            data_ptr=data_ptr+cur_payload;

        }else{
            header->next_header=protocol;
            memcpy(m->data+m->offset+header_size+cur_payload,data_ptr,data_size);
            cur_payload+=data_size;

            m->end=m->tail=MBUF_BEGIN+data_size+40;
        }

        //DBG("tot %d\r\n",m->end-m->begin);

        header->payload_len=htons(data_size);

        netpkt_send(m,protocol,1);
    }

    return rs;
}

int ipv6_mtu_set(unsigned short mtu)
{
    ipv6_mtu=mtu;
    return 0;
}
