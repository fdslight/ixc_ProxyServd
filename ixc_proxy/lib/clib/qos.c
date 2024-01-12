#include <string.h>
#include <arpa/inet.h>

#include "qos.h"
#include "debug.h"
#include "proxy.h"

#include "../../../pywind/clib/netutils.h"
#include "../../../pywind/clib/sysloop.h"

static struct qos qos;
static int qos_is_initialized = 0;
static struct sysloop *qos_sysloop=NULL;

static void qos_sysloop_cb(struct sysloop *lp)
{
    // 弹出数据包
    qos_pop();
}

inline static int qos_calc_slot(void *header,int is_ipv6)
{
    struct netutil_iphdr *iphdr;
    struct netutil_ip6hdr *ip6hdr;
    struct netutil_udphdr *udphdr;
    int hdr_len;

    unsigned long long v;
    unsigned char next_header,*s=header;
    unsigned char buf[8]={
        0,0,0,0,
        0,0,0,0
    };

    if(is_ipv6){
        ip6hdr=header;
        next_header=ip6hdr->next_header;
        hdr_len=40;
        
        buf[0]=ip6hdr->src_addr[14];
        buf[1]=ip6hdr->src_addr[15];
        buf[2]=ip6hdr->dst_addr[14];
        buf[3]=ip6hdr->dst_addr[15];
    }else{
        iphdr=header;
        next_header=iphdr->protocol;
        hdr_len=(iphdr->ver_and_ihl & 0x0f) * 4;

        buf[0]=iphdr->src_addr[2];
        buf[1]=iphdr->src_addr[3];
        buf[2]=iphdr->dst_addr[2];
        buf[3]=iphdr->dst_addr[3];
    }

    switch (next_header){
        case 6:
        case 17:
        case 136:
            // TCP头部,UDP和UDPLite端口部分定义相同,这里只需要端口部分,直接用UDP协议定义即可
            udphdr=(struct netutil_udphdr *)(s+hdr_len);
            
            memcpy(&buf[4],&(udphdr->src_port),2);
            memcpy(&buf[6],&(udphdr->dst_port),2);
        default:
            break;
    }
    
    memcpy(&v,buf,8);

    return v % QOS_SLOT_NUM;
}

static void qos_put(struct mbuf *m,void *header,int is_ipv6)
{
    int slot_no;
    struct qos_slot *slot_obj;

    m->next=NULL;
    slot_no=qos_calc_slot(header,is_ipv6);
    slot_obj=qos.slot_objs[slot_no];

    if(!slot_obj->is_used){
        slot_obj->next=NULL;
        
        slot_obj->is_used=1;
        slot_obj->mbuf_first=m;
        slot_obj->mbuf_last=m;

        slot_obj->next=qos.slot_head;
        qos.slot_head=slot_obj;
        return;
    }

    slot_obj->mbuf_last->next=m;
    slot_obj->mbuf_last=m;
}

static void qos_add_for_ip(struct mbuf *m)
{
    struct netutil_iphdr *iphdr = (struct netutil_iphdr *)(m->data + m->offset);

    qos_put(m,iphdr,0);
}

static void qos_add_for_ipv6(struct mbuf *m)
{
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);

    qos_put(m,header,1);
}

int qos_init(void)
{
    struct qos_slot *slot;
    bzero(&qos, sizeof(struct qos));
    qos_is_initialized = 1;

    for (int n = 0; n < QOS_SLOT_NUM; n++){
        slot = malloc(sizeof(struct qos_slot));
        if (NULL == slot){
            qos_uninit();
            STDERR("cannot create slot for qos\r\n");
            break;
        }
        bzero(slot,sizeof(struct qos_slot));
        slot->slot=n;
        qos.slot_objs[n]=slot;
    }
    qos_sysloop=sysloop_add(qos_sysloop_cb,NULL);
    if(NULL==qos_sysloop){
        qos_uninit();
        STDERR("cannot add to sysloop\r\n");
        return -1;
    }

    return 0;
}

void qos_uninit(void)
{
    if(NULL!=qos_sysloop) sysloop_del(qos_sysloop);
    qos_is_initialized = 0;
}

void qos_add(struct mbuf *m)
{
    if (m->is_ipv6){
        qos_add_for_ipv6(m);
    }else{
        qos_add_for_ip(m);
    }
}

void qos_pop(void)
{
    struct qos_slot *slot_first=qos.slot_head;
    struct qos_slot *slot_obj=slot_first;
    struct qos_slot *slot_old=qos.slot_head,*t_slot;
    struct mbuf *m=NULL,*t;

    while(NULL!=slot_obj){
        m=slot_obj->mbuf_first;

        // 这里需要创建一个临时变量,防止其他节点修改m->next导致内存访问出现问题
        t=m->next;
        
        netpkt_send(m);

        m=t;
        // 如果数据未发送完毕,那么跳转到下一个
        if(NULL!=m){
            slot_obj->mbuf_first=m;
            slot_old=slot_obj;
            slot_obj=slot_obj->next;
            continue;
        }
        // 重置slot_obj
        slot_obj->is_used=0;
        slot_obj->mbuf_first=NULL;
        slot_obj->mbuf_last=NULL;

        // 如果不是第一个的处置方式
        if(slot_obj!=slot_first){
            slot_old->next=slot_obj->next;
            t_slot=slot_obj->next;
            slot_obj->next=NULL;
            slot_obj=t_slot;
            continue;
        }

        qos.slot_head=slot_obj->next;
        t_slot=slot_obj->next;
        slot_obj->next=NULL;
        slot_obj=t_slot;
        slot_first=qos.slot_head;
        slot_old=slot_first;
    }

}

int qos_have_data(void)
{
    if(NULL!=qos.slot_head) return 1;
    return 0;
}