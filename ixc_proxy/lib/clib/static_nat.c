
#include<string.h>

#include "debug.h"
#include "static_nat.h"

#include "../../../pywind/clib/netutils.h"

static struct static_nat static_nat;
static int static_nat_is_initialized=0;
static struct time_wheel static_nat_time_wheel;


/// 重写IPv6地址
static void static_nat_rewrite_ip6(struct netutil_ip6hdr *header,unsigned char *new_addr,int is_src)
{
    unsigned char old_addr[16];
    unsigned char *csum_ptr;

    if(is_src) memcpy(old_addr,header->src_addr,16);
    else memcpy(old_addr,header->dst_addr,16);

}

/// 发送到下一个IPv4节点处理
static void static_nat_send_next_for_v4(struct mbuf *m,struct netutil_iphdr *header)
{

}

/// 发送到下一个IPv6节点处理
static void static_nat_send_next_for_v6(struct mbuf *m,struct netutil_ip6hdr *header)
{

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
        rewrite_ip_addr(header,r->lan_addr2,is_src);

        static_nat_send_next_for_v4(m,header);
        return;
    }

    if(r){
        rewrite_ip_addr(header,r->lan_addr1,is_src);
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
    memcmp(r->lan_addr2,ip_record->address,4);

    rewrite_ip_addr(header,r->lan_addr2,is_src);

    static_nat_send_next_for_v4(m,header);
}


static void static_nat_handle_v6(struct mbuf *m)
{
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);
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
    
    r=map_find(static_nat.natv6,key,&is_found);

    // 如果来自于WAN并且无映射记录那么丢弃数据包
    if(m->from==MBUF_FROM_WAN && r==NULL){
        mbuf_put(m);
        return;
    }

    if(m->from==MBUF_FROM_WAN){
        r->up_time=time(NULL);
        static_nat_rewrite_ip6(header,ip_record->address,is_src);
        static_nat_send_next_for_v6(m,header);
        return;
    }

    if(r){
        static_nat_rewrite_ip6(header,ip_record->address,is_src);
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

    memcpy(r->lan_addr1,header->src_addr,4);
    memcmp(r->lan_addr2,ip_record->address,4);

    static_nat_rewrite_ip6(header,ip_record->address,is_src);

    static_nat_send_next_for_v6(m,header);
}

static void static_nat_timeout_cb(void *data)
{

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
