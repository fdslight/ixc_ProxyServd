
#include<string.h>

#include "debug.h"
#include "static_nat.h"
#include "udp.h"
#include "proxy.h"
#include "qos.h"

#include "../../../pywind/clib/netutils.h"
#include "../../../pywind/clib/sysloop.h"

static struct static_nat static_nat;
static int static_nat_is_initialized=0;
static struct time_wheel static_nat_time_wheel;
static struct sysloop *static_nat_sysloop=NULL;

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
    }else{
        memcpy(old_addr,header->dst_addr,16);
        memcpy(header->dst_addr,new_addr,16);    
    }

    old_u16addr=(unsigned short *)(old_addr);

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

    memcpy(&csum,csum_ptr,2);

    for(int n=0;n<8;n++){
        csum=csum_calc_incre(*old_u16addr,*new_u16addr++,csum);
    }

    *((unsigned short *)(csum_ptr))=csum;
}

static void static_nat_sysloop_cb(struct sysloop *loop)
{
    //DBG_FLAGS;
    time_wheel_handle(&static_nat_time_wheel);
    //DBG_FLAGS;
}

/// 发送到下一个IPv4节点处理
static void static_nat_send_next_for_v4(struct mbuf *m,struct netutil_iphdr *header)
{
    if(header->protocol==17 || header->protocol==136){
        udp_handle(m,0);
        return;
    }

    qos_add(m);
}

/// 发送到下一个IPv6节点处理
static void static_nat_send_next_for_v6(struct mbuf *m,struct netutil_ip6hdr *header)
{
    if(header->next_header==17 || header->next_header==136){
        udp_handle(m,1);
        return;
    }

    qos_add(m);
}


static void static_nat_handle_v4(struct mbuf *m)
{
    struct netutil_iphdr *header=(struct netutil_iphdr *)(m->data+m->offset);
    struct static_nat_record *r=NULL;
    struct ipalloc_record *ip_record;
    struct time_data *tdata;
    char is_found;
    char key[20];
    int is_src=0,rs;

    if(m->from==MBUF_FROM_LAN) {
        memcpy(key,m->id,16);
        memcpy(&key[16],header->src_addr,4);
        is_src=1;
        r=map_find(static_nat.natv4_lan2wan,key,&is_found);
    }else{
        //DBG_FLAGS;
        memcpy(key,header->dst_addr,4);
        //PRINT_IP("dest ",header->dst_addr);
        r=map_find(static_nat.natv4_wan2lan,key,&is_found);

        if(NULL==r){
            DBG_FLAGS;
            mbuf_put(m);
            return;
        }
    }
    //DBG_FLAGS;
    if(m->from==MBUF_FROM_WAN){
        memcpy(m->id,r->id,16);
        rewrite_ip_addr(header,r->lan_addr1,is_src);

        static_nat_send_next_for_v4(m,header);
        return;
    }
    //DBG_FLAGS;
    if(r){
        r->up_time=time(NULL);
        rewrite_ip_addr(header,r->lan_addr2,is_src);
        static_nat_send_next_for_v4(m,header);
        return;
    }
    //DBG_FLAGS;
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

    PRINT_IP("alloc IP address ",ip_record->address);
    tdata=time_wheel_add(&static_nat_time_wheel,r,10);

    if(NULL==tdata){
        STDERR("cannot add to timer\r\n");
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,0);
        return;
    }

    rs=map_add(static_nat.natv4_lan2wan,key,r);
    if(0!=rs){
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,0);
        tdata->is_deleted=1;
        STDERR("cannot add to map\r\n");
        return;
    }
    
    rs=map_add(static_nat.natv4_wan2lan,(char *)(ip_record->address),r);
    if(0!=rs){
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,0);
        map_del(static_nat.natv4_lan2wan,key,NULL);
        tdata->is_deleted=1;
        STDERR("cannot add to map\r\n");
        return;
    }

    r->ip_record=ip_record;
    r->up_time=time(NULL);
    r->refcnt=2;
    r->tdata=tdata;
    r->is_ipv6=0;

    memcpy(r->lan_addr1,header->src_addr,4);
    memcpy(r->lan_addr2,ip_record->address,4);
    memcpy(r->id,m->id,16);

    rewrite_ip_addr(header,r->lan_addr2,is_src);

    static_nat_send_next_for_v4(m,header);
}


static void static_nat_handle_v6(struct mbuf *m)
{
    //DBG_FLAGS;
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);
    struct static_nat_record *r;
    struct ipalloc_record *ip_record;
    struct time_data *tdata;
    char is_found;
    char key[32];
    int is_src=0,rs;

    //DBG_FLAGS;

    if(m->from==MBUF_FROM_LAN) {
        memcpy(key,m->id,16);
        memcpy(&key[16],header->src_addr,16);
        is_src=1;
        r=map_find(static_nat.natv6_lan2wan,key,&is_found);
    }else{
        memcpy(key,header->dst_addr,16);
        r=map_find(static_nat.natv6_wan2lan,key,&is_found);

        if(NULL==r){
            mbuf_put(m);
            return;
        }
    }

    if(m->from==MBUF_FROM_WAN){
        memcpy(m->id,r->id,16);
        static_nat_rewrite_ip6(header,r->lan_addr1,is_src);
        static_nat_send_next_for_v6(m,header);
        return;
    }

    if(r){
        r->up_time=time(NULL);
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

    PRINT_IP6("alloc IPv6 address ",ip_record->address);

    tdata=time_wheel_add(&static_nat_time_wheel,r,10);

    if(NULL==tdata){
        STDERR("cannot add to timer\r\n");
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,1);
        return;
    }

    rs=map_add(static_nat.natv6_lan2wan,key,r);
    if(0!=rs){
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,1);
        tdata->is_deleted=1;
        STDERR("cannot add to map\r\n");
        return;
    }
    
    rs=map_add(static_nat.natv6_wan2lan,(char *)(ip_record->address),r);
    if(0!=rs){
        mbuf_put(m);
        free(r);
        ipalloc_free(ip_record,1);
        map_del(static_nat.natv6_lan2wan,key,NULL);
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
    memcpy(r->id,m->id,16);

    static_nat_rewrite_ip6(header,r->lan_addr2,is_src);
    static_nat_send_next_for_v6(m,header);
}

static void static_nat_del_cb(void *data)
{
    //DBG_FLAGS;
    struct static_nat_record *r=data;
    struct time_data *tdata=r->tdata;
    //DBG_FLAGS;
    if(NULL!=tdata) tdata->is_deleted=1;
    //DBG_FLAGS;
    r->refcnt-=1;

    if(0==r->refcnt){
        DBG_FLAGS;
        ipalloc_free(r->ip_record,r->is_ipv6);
        free(r);
        return;
    }
}

static void static_nat_timeout_cb(void *data)
{
    struct static_nat_record *r=data;
    struct time_data *tdata=r->tdata;
   
    struct map *m_lan2wan=r->is_ipv6?static_nat.natv6_lan2wan:static_nat.natv4_lan2wan;
    struct map *m_wan2lan=r->is_ipv6?static_nat.natv6_wan2lan:static_nat.natv4_wan2lan;

    time_t now=time(NULL);

    char key[32];

    memcpy(key,r->id,16);

    //DBG_FLAGS;

    if(r->is_ipv6){
        memcpy(&key[16],r->lan_addr1,16);
    }else{
        memcpy(&key[16],r->lan_addr1,4);
    }
    
    // 如果超时那么直接删除数据
    if(now-r->up_time<STATIC_NAT_TIMEOUT){
        tdata=time_wheel_add(&static_nat_time_wheel,data,10);
        if(NULL==tdata){
            STDERR("cannot add to time wheel\r\n");
            map_del(m_lan2wan,key,static_nat_del_cb);
            map_del(m_wan2lan,(char *)r->lan_addr2,static_nat_del_cb);
            return;
        }
        if(r->is_ipv6){
            PRINT_IP6(" ",r->lan_addr1);
        }else{
            PRINT_IP(" ",r->lan_addr1);
        }
        r->tdata=tdata;
        DBG_FLAGS;
        return;
    }

    if(r->is_ipv6){
        PRINT_IP6(" ",r->lan_addr1);
    }else{
        PRINT_IP(" ",r->lan_addr1);
    }

    map_del(m_lan2wan,key,static_nat_del_cb);
    map_del(m_wan2lan,(char *)r->lan_addr2,static_nat_del_cb);
}

int static_nat_init(void)
{
    int rs=time_wheel_new(&static_nat_time_wheel,STATIC_NAT_TIMEOUT*2/10,10,static_nat_timeout_cb,256);
    struct map *m;

    if(rs!=0){
        STDERR("cannot init time wheel\r\n");
        return -1;
    }

    static_nat_sysloop=sysloop_add(static_nat_sysloop_cb,NULL);
    if(NULL==static_nat_sysloop){
        STDERR("cannot add to sysloop");
        time_wheel_release(&static_nat_time_wheel);
        return -1;
    }

    bzero(&static_nat,sizeof(struct static_nat));

    rs=map_new(&m,32);
    if(0!=rs){
        STDERR("cannot create map for IPv6 LAN2WAN");
        sysloop_del(static_nat_sysloop);
        time_wheel_release(&static_nat_time_wheel);
        return -1;
    }
    static_nat.natv6_lan2wan=m;

    rs=map_new(&m,16);
    if(0!=rs){
        STDERR("cannot create map for IPv6 WAN2LAN");
        sysloop_del(static_nat_sysloop);
        map_release(static_nat.natv6_lan2wan,NULL);

        time_wheel_release(&static_nat_time_wheel);
        return -1;
    }
    static_nat.natv6_wan2lan=m;

    rs=map_new(&m,20);
    if(0!=rs){
        STDERR("cannot create map for IPv4 LAN2WAN");
        sysloop_del(static_nat_sysloop);

        map_release(static_nat.natv6_lan2wan,NULL);
        map_release(static_nat.natv6_wan2lan,NULL);

        time_wheel_release(&static_nat_time_wheel);
        return -1;
    }
    static_nat.natv4_lan2wan=m;

    rs=map_new(&m,4);
    if(0!=rs){
        STDERR("cannot create map for IPv4 WAN2LANs");
        sysloop_del(static_nat_sysloop);

        map_release(static_nat.natv6_lan2wan,NULL);
        map_release(static_nat.natv6_wan2lan,NULL);
        map_release(static_nat.natv4_lan2wan,NULL);

        time_wheel_release(&static_nat_time_wheel);
        return -1;
    }
    static_nat.natv4_wan2lan=m;

    static_nat_is_initialized=1;
    return 0;
}

void static_nat_uninit(void)
{
    sysloop_del(static_nat_sysloop);

    map_release(static_nat.natv4_lan2wan,static_nat_timeout_cb);
    map_release(static_nat.natv4_wan2lan,static_nat_timeout_cb);

    map_release(static_nat.natv6_lan2wan,static_nat_timeout_cb);
    map_release(static_nat.natv6_wan2lan,static_nat_timeout_cb);

    time_wheel_release(&static_nat_time_wheel);

    static_nat_is_initialized=1;
}

void static_nat_handle(struct mbuf *m)
{
    //DBG_FLAGS;
    if(m->is_ipv6) static_nat_handle_v6(m);
    else static_nat_handle_v4(m);
}

/// 把IP地址和用户绑定
int static_nat_bind(unsigned char *id,unsigned char *address,int is_ipv6)
{
    return 0;
}