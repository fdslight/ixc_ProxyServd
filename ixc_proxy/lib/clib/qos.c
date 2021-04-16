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

inline static int qos_calc_slot(unsigned char a, unsigned char b, unsigned char c,unsigned char d)
{
    unsigned int v= (a << 24) | (b<<16) | (c<<8) | d;
    int slot_num= v % QOS_SLOT_NUM;

    return slot_num;
}

static void qos_put(struct mbuf *m,unsigned char a,unsigned char b,unsigned char c,unsigned char d)
{
    int slot_no;
    struct qos_slot *slot_obj;

    m->next=NULL;
    slot_no=qos_calc_slot(a,b,c,d);
    slot_obj=qos.slot_objs[slot_no];

    if(!slot_obj->is_used){
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

    qos_put(m,iphdr->src_addr[3],iphdr->dst_addr[1],iphdr->dst_addr[2],iphdr->dst_addr[3]);
}

static void qos_add_for_ipv6(struct mbuf *m)
{
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);

    qos_put(m,header->src_addr[15],header->dst_addr[13],header->dst_addr[14],header->dst_addr[15]);
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
    struct qos_slot *slot_old=qos.slot_head,*t;
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
            slot_old=slot_obj;
            t=slot_obj->next;
            slot_obj->next=NULL;
            slot_obj=t;
            continue;
        }

        qos.slot_head=slot_obj->next;
        t=slot_obj->next;
        slot_obj->next=NULL;
        slot_obj=t;
        slot_first=qos.slot_head;
        slot_old=slot_first;
    }

}

int qos_have_data(void)
{
    if(NULL!=qos.slot_head) return 1;
    return 0;
}