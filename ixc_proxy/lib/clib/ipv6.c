#include<string.h>
#include<arpa/inet.h>
#include<time.h>

#include "ipv6.h"
#include "ip6unfrag.h"
#include "udp.h"
#include "proxy.h"
#include "static_nat.h"
#include "qos.h"
#include "ipalloc.h"
#include "debug.h"

#include "../../../pywind/clib/debug.h"
#include "../../../pywind/clib/netutils.h"

static int ipv6_mtu=1280;
static int ipv6_enable_udplite=0;


static void ipv6_icmpv6_packet_too_big_send(struct mbuf *m,struct netutil_ip6hdr *ip6_header)
{
    unsigned char buffer[512];
    struct icmpv6_pmtu_header{
        unsigned char type;
        unsigned char code;
        unsigned short csum;
        unsigned int mtu;
    };
    unsigned short csum;

    struct netutil_ip6_ps_header *ps_header=(struct netutil_ip6_ps_header *)buffer;
    struct icmpv6_pmtu_header *icmp_header=(struct icmpv6_pmtu_header *)(buffer+40);

    bzero(ps_header,sizeof(struct netutil_ip6_ps_header));

    memcpy(ps_header->src_addr,ip6_header->dst_addr,16);
    memcpy(ps_header->dst_addr,ip6_header->src_addr,16);

    ps_header->next_header=58;
    ps_header->length=htons(48);

    icmp_header->type=2;
    icmp_header->code=0;
    icmp_header->csum=0;
    icmp_header->mtu=htonl(ipv6_mtu);

    memcpy(buffer+48,ip6_header,40);
    
    csum=csum_calc((unsigned short *)buffer,88);
    icmp_header->csum=htons(csum);

    memcpy(ip6_header->src_addr,ps_header->src_addr,16);
    memcpy(ip6_header->dst_addr,ps_header->dst_addr,16);

    memcpy(m->data+m->offset+40,buffer+40,48);

    m->end=m->tail=m->offset+88;

    m->from=MBUF_FROM_WAN;

    qos_add(m);

    STDERR("ICMP TOO BIG---------------------------------\r\n");
}

void ipv6_handle(struct mbuf *m)
{
    struct netutil_ip6hdr *header;
    struct netutil_ip6_frag_header *frag_header=NULL;
    int payload_len=0;
    unsigned char next_header;

    DBG_FLAGS;

    if(!ipalloc_isset_ip(1)){
        mbuf_put(m);
        return;
    }

    if(m->tail-m->offset<41){
        mbuf_put(m);
        return;
    }

    m->is_ipv6=1;
    header=(struct netutil_ip6hdr *)(m->data+m->offset);
    next_header=header->next_header;

    payload_len=ntohs(header->payload_len);
    if(m->tail-m->offset!=(payload_len+40)){
        mbuf_put(m);
        return;
    }

    if(header->dst_addr[0]==0){
        mbuf_put(m);
        return;
    }

    // 源地址和目标地址不能一样
    if(!memcmp(header->src_addr,header->dst_addr,16)){
        mbuf_put(m);
        return;
    }

    //PRINT_IP6(" ",header->dst_addr);
    
    // 如果是同一个局域网丢弃数据包
    if(ipalloc_is_lan(header->dst_addr,1) && m->from==MBUF_FROM_LAN){
        mbuf_put(m);
        return;
    }

    // 禁用WAN的UDP和UDPLite数据包
    if(m->from==MBUF_FROM_WAN && (header->next_header==17 || header->next_header==136)){
        //PRINT_IP6(" ",header->dst_addr);
        mbuf_put(m);
        return;
    }

    //限制IPv6 MTU长度
    if((m->tail-m->offset>ipv6_mtu) && MBUF_FROM_LAN==m->from && next_header==6){
        ipv6_icmpv6_packet_too_big_send(m,header);
        return;
    }

    // 只对LAN重组
    if(next_header==44 && m->from==MBUF_FROM_LAN){
        if(m->tail-m->offset<49){
            mbuf_put(m);
            return;
        }
        //DBG_FLAGS;
        frag_header=(struct netutil_ip6_frag_header *)(m->data+m->offset+40);
        next_header=frag_header->next_header;

        m=ip6unfrag_add(m);
        //DBG_FLAGS;
        if(NULL==m) return;
    }
    
    switch(next_header){
        case 6:
        case 58:
            //PRINT_IP6(" ",header->dst_addr);
            static_nat_handle(m);
            //DBG_FLAGS;
            break;
        case 17:
            udp_handle(m,1);
            break;
        case 136:
            if(ipv6_enable_udplite) udp_handle(m,1);
            else mbuf_put(m);
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

        qos_add(m);
    }

    return rs;
}

int ipv6_mtu_set(unsigned short mtu)
{
    ipv6_mtu=mtu;
    return 0;
}
