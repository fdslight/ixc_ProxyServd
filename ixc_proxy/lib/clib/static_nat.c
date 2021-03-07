
#include<string.h>

#include "debug.h"
#include "static_nat.h"
#include "udp.h"
#include "proxy.h"

#include "../../../pywind/clib/netutils.h"

static struct static_nat static_nat;
static int static_nat_is_initialized=0;
static struct time_wheel static_nat_time_wheel;

/// 重写IPv6地址
static void static_nat_rewrite_ip6(struct netutil_ip6hdr *header,unsigned char *new_addr,int is_src)
{
    unsigned char old_addr[16];
    unsigned char *csum_ptr;
    unsigned short csum;
    unsigned char *ptr=(unsigned char *)(header);
    unsigned short *old_u16addr,*new_u16addr=(unsigned short *)new_addr;

    int flags=1;

    if(is_src) {
        memcpy(old_addr,header->src_addr,16);
        memcpy(header->src_addr,new_addr,16);

        old_u16addr=(unsigned short *)(header->src_addr);
    }else{
        memcpy(old_addr,header->dst_addr,16);
        memcpy(header->dst_addr,new_addr,16);

        old_u16addr=(unsigned short *)(header->dst_addr);
    }

    switch(header->next_header){
        case 6:
            csum_ptr=ptr+46;
            break;
        case 17:
            csum_ptr=ptr+56;
            break;
        case 58:
            csum_ptr=ptr+2;
            break;
        default:
            flags=0;
            break;
    }

    // 不需要重写传输层校验和直接跳过
    if(!flags) return;
    csum=*((unsigned short *)(csum_ptr));

    for(int n=0;n<16;n++){
        csum=csum_calc_incre(*old_u16addr,*new_u16addr++,csum);
    }

    *((unsigned short *)(csum_ptr))=csum;
}

/// 发送到下一个IPv4节点处理
static void static_nat_send_next_for_v4(struct mbuf *m,struct netutil_iphdr *header)
{
    if(header->protocol==17 || header->protocol==136){
        udp_handle(m,0);
        return;
    }

    netpkt_send(m);
}

/// 发送到下一个IPv6节点处理
static void static_nat_send_next_for_v6(struct mbuf *m,struct netutil_ip6hdr *header)
{
    if(header->next_header==17 || header->next_header==136){
        udp_handle(m,1);
        return;
    }

    netpkt_send(m);
}


static void static_nat_handle_v4(struct mbuf *m)
{
    struct netutil_iphdr *header=(struct netutil_iphdr *)(m->data+m->offset);
    struct static_nat_record *r;
    struct ipalloc_record *ip_record;
    struct time_data *tdata;
    char is_found;
    char *key;
    int is_src=0,rs;

    if(m->from==MBUF_FROM_LAN) {
        key=(char *)(header->src_addr);
        is_src=1;
    }else{
        key=(char *)(header->dst_addr);
    }
    
    r=map_find(static_nat.natv4,key,&is_found);

    // 如果来自于WAN并且无映射记录那么丢弃数据包
    if(m->from==MBUF_FROM_WAN && r==NULL){
        mbuf_put(m);
        return;
    }

    if(m->from==MBUF_FROM_WAN){
        r->up_time=time(NULL);
        rewrite_ip_addr(header,r->lan_addr1,is_src);

        static_nat_send_next_for_v4(m,header);
        return;
    }

    if(r){
        rewrite_ip_addr(header,r->lan_addr2,is_src);
        static_nat_send_next_for_v4(m,header);
        return;
    }
    
    r=malloc(sizeof(struct static_nat_record));
    if(NULL==r){
        STDERR("cannot malloc struct static_nat_record\r\n");
        mbuf_put(m);
        return;
    }

    bzero(r,sizeof(struct static_nat_record));

    ip_record=ipalloc_alloc(0);
    if(NULL==ip_record){
        STDERR("cannot get new ip address\r\n");
        mbuf_put(m);
        return;
    }

    tdata=time_wheel_add(&static_nat_time_wheel,r,STATIC_NAT_TIMEOUT);

    if(NULL==tdata){
        STDERR("cannot add to timer\r\n");
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,0);
        return;
    }

    rs=map_add(static_nat.natv4,(char *)(header->src_addr),r);
    if(0!=rs){
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,0);
        tdata->is_deleted=1;
        STDERR("cannot add to map\r\n");
        return;
    }
    
    rs=map_add(static_nat.natv4,(char *)(header->dst_addr),r);
    if(0!=rs){
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,0);
        map_del(static_nat.natv4,(char *)(header->src_addr),NULL);
        tdata->is_deleted=1;
        STDERR("cannot add to map\r\n");
        return;
    }

    r->ip_record=ip_record;
    r->up_time=time(NULL);
    r->refcnt=2;
    r->tdata=tdata;

    memcpy(r->lan_addr1,header->src_addr,4);
    memcpy(r->lan_addr2,ip_record->address,4);

    rewrite_ip_addr(header,r->lan_addr2,is_src);

    static_nat_send_next_for_v4(m,header);
}


static void static_nat_handle_v6(struct mbuf *m)
{
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);
    struct static_nat_record *r;
    struct ipalloc_record *ip_record;
    struct time_data *tdata;
    char is_found;
    char *key;
    int is_src=0,rs;

    if(m->from==MBUF_FROM_LAN) {
        key=(char *)(header->src_addr);
        is_src=1;
    }else{
        key=(char *)(header->dst_addr);
    }
    
    r=map_find(static_nat.natv6,key,&is_found);

    // 如果来自于WAN并且无映射记录那么丢弃数据包
    if(m->from==MBUF_FROM_WAN && r==NULL){
        mbuf_put(m);
        return;
    }

    if(m->from==MBUF_FROM_WAN){
        r->up_time=time(NULL);
        ip_record=r->ip_record;
        static_nat_rewrite_ip6(header,r->lan_addr1,is_src);
        static_nat_send_next_for_v6(m,header);
        return;
    }

    if(r){
        static_nat_rewrite_ip6(header,r->lan_addr2,is_src);
        static_nat_send_next_for_v6(m,header);
        return;
    }
    
    r=malloc(sizeof(struct static_nat_record));
    if(NULL==r){
        STDERR("cannot malloc struct static_nat_record\r\n");
        mbuf_put(m);
        return;
    }

    bzero(r,sizeof(struct static_nat_record));

    ip_record=ipalloc_alloc(1);
    if(NULL==ip_record){
        STDERR("cannot get new ip address\r\n");
        mbuf_put(m);
        return;
    }

    tdata=time_wheel_add(&static_nat_time_wheel,r,STATIC_NAT_TIMEOUT);

    if(NULL==tdata){
        STDERR("cannot add to timer\r\n");
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,0);
        return;
    }

    rs=map_add(static_nat.natv6,(char *)(header->src_addr),r);
    if(0!=rs){
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,1);
        tdata->is_deleted=1;
        STDERR("cannot add to map\r\n");
        return;
    }
    
    rs=map_add(static_nat.natv6,(char *)(header->dst_addr),r);
    if(0!=rs){
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,1);
        map_del(static_nat.natv6,(char *)(header->src_addr),NULL);
        tdata->is_deleted=1;
        STDERR("cannot add to map\r\n");
        return;
    }

    r->ip_record=ip_record;
    r->up_time=time(NULL);
    r->refcnt=2;
    r->tdata=tdata;
    r->is_ipv6=1;

    memcpy(r->lan_addr1,header->src_addr,16);
    memcpy(r->lan_addr2,ip_record->address,16);

    static_nat_rewrite_ip6(header,ip_record->address,is_src);

    static_nat_send_next_for_v6(m,header);
}

static void static_nat_del_cb(void *data)
{
    struct static_nat_record *r=data;
    struct time_data *tdata=r->tdata;

    if(NULL!=tdata) tdata->is_deleted=1;
    r->refcnt-=1;

    if(0==r->refcnt){
        ipalloc_free(r->ip_record,r->is_ipv6);
        free(r);
        return;
    }
}

static void static_nat_timeout_cb(void *data)
{
    struct static_nat_record *r=data;
    struct time_data *tdata=r->tdata;
    time_t now=time(NULL);

    struct map *m=r->is_ipv6?static_nat.natv6:static_nat.natv4;

    // 如果超时那么直接删除数据
    if(now-r->up_time<STATIC_NAT_TIMEOUT){
        tdata=time_wheel_add(&static_nat_time_wheel,data,10);
        if(NULL==tdata){
            STDERR("cannot add to time wheel\r\n");
            map_del(m,(char *)r->lan_addr1,static_nat_del_cb);
            map_del(m,(char *)r->lan_addr2,static_nat_del_cb);
            return;
        }

        r->tdata=tdata;
        return;
    }

    DBG_FLAGS;

    map_del(m,(char *)r->lan_addr1,static_nat_del_cb);
    map_del(m,(char *)r->lan_addr2,static_nat_del_cb);
}

int static_nat_init(void)
{
    int rs=time_wheel_new(&static_nat_time_wheel,STATIC_NAT_TIMEOUT*2/10,10,static_nat_timeout_cb,256);
    struct map *m;

    if(rs!=0){
        STDERR("cannot init time wheel\r\n");
        return -1;
    }

    bzero(&static_nat,sizeof(struct static_nat));

    rs=map_new(&m,16);
    if(0!=rs){
        STDERR("cannot create map for IPv6");
        time_wheel_release(&static_nat_time_wheel);
        return -1;
    }
    static_nat.natv6=m;

    rs=map_new(&m,4);
    if(0!=rs){
        STDERR("cannot create map for IPv4");
        map_release(static_nat.natv6,NULL);
        time_wheel_release(&static_nat_time_wheel);
        return -1;
    }
    static_nat_is_initialized=1;
    return 0;
}

void static_nat_uninit(void)
{
    map_release(static_nat.natv4,static_nat_timeout_cb);
    map_release(static_nat.natv6,static_nat_timeout_cb);

    time_wheel_release(&static_nat_time_wheel);
    static_nat_is_initialized=1;
}

void static_nat_handle(struct mbuf *m)
{
    if(m->is_ipv6) static_nat_handle_v6(m);
    else static_nat_handle_v4(m);
}
