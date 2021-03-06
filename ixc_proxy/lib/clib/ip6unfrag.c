#include<string.h>
#include<stdlib.h>

#include "ip6unfrag.h"
#include "mbuf.h"

#include "../../../pywind/clib/timer.h"
#include "../../../pywind/clib/netutils.h"
#include "../../../pywind/clib/sysloop.h"
#include "../../../pywind/clib/debug.h"

static struct ip6unfrag ip6unfrag;
static int ip6unfrag_is_initialized=0;
static struct time_wheel ip6unfrag_time_wheel;
static struct sysloop *ip6unfrag_sysloop;

static void ip6unfrag_map_del_cb(void *data)
{
    struct mbuf *m=data;
    struct time_data *tdata=m->priv_data;
    
    tdata->is_deleted=1;

    mbuf_put(m);
}

static void ipunfrag_timeout_cb(void *data)
{
    char key[IP6UNFRAG_KEYSIZE];
    struct mbuf *m=data;
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);

    memcpy(&key[0],header->src_addr,16);
    memcpy(&key[16],header->dst_addr,16);
    memcpy(&key[32],&(m->priv_flags),4);

    map_del(ip6unfrag.m,key,ip6unfrag_map_del_cb);
}

static void ip6unfrag_sysloop_cb(struct sysloop *loop)
{
    time_wheel_handle(&ip6unfrag_time_wheel);
}

int ip6unfrag_init(void)
{
    struct map *m;
    int rs=map_new(&m,IP6UNFRAG_KEYSIZE);

    if(0!=rs){
        STDERR("cannot create map for ipunfrag\r\n");
        return -1;
    }

    // 这里的时间需要大于10s,因为系统IO阻塞时间为10s
    rs=time_wheel_new(&ip6unfrag_time_wheel,60,1,ipunfrag_timeout_cb,4096);
    if(0!=rs){
        map_release(m,NULL);
        STDERR("cannot create timer\r\n");
        return -1;
    }

    ip6unfrag_sysloop=sysloop_add(ip6unfrag_sysloop_cb,NULL);
    if(NULL==ip6unfrag_sysloop){
        time_wheel_release(&ip6unfrag_time_wheel);
        map_release(m,NULL);
        STDERR("cannot add to sysloop\r\n");
        return -1;
    }

    bzero(&ip6unfrag,sizeof(struct ip6unfrag));

    ip6unfrag.m=m;
    ip6unfrag_is_initialized=1;

    return 0;
}

void ip6unfrag_uninit(void)
{
    map_release(ip6unfrag.m,ip6unfrag_map_del_cb);
    time_wheel_release(&ip6unfrag_time_wheel);

    ip6unfrag_is_initialized=0;
}

struct mbuf *ip6unfrag_add(struct mbuf *m)
{
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);
    struct netutil_ip6_frag_header *frag_header=NULL;
    struct mbuf *new_mbuf;
    unsigned short frag_off,M,frag_info,payload_len;
    char key[IP6UNFRAG_KEYSIZE],is_found;
    struct time_data *tdata;
    int rs;

    // 下一个可选头部必须为分帧头
    if(header->next_header!=44) return m;
    frag_header=(struct netutil_ip6_frag_header *)(m->data+m->offset+40);

    frag_info=ntohs(frag_header->frag_off);
    M=frag_info & 0x0001;
    frag_off=(frag_info & 0xfff8)>>3;
    payload_len=ntohs(header->payload_len);

    // 生成一个唯一ID
    memcpy(&key[0],header->src_addr,16);
    memcpy(&key[16],header->dst_addr,16);
    memcpy(&key[32],&(frag_header->id),4);

    // 处理第一个分片
    if(frag_off==0){
        new_mbuf=mbuf_get();
        if(NULL==new_mbuf){
            STDERR("cannot get mbuf from ip6unfrag\r\n");
            mbuf_put(m);
            return NULL;
        }

        rs=map_add(ip6unfrag.m,key,new_mbuf);
        if(rs!=0){
            mbuf_put(new_mbuf);
            mbuf_put(m);
            STDERR("cannot to map\r\n");
            return NULL;
        }

        //DBG_FLAGS;
        tdata=time_wheel_add(&ip6unfrag_time_wheel,new_mbuf,1);
        if(NULL==tdata){
            mbuf_put(m);
            mbuf_put(new_mbuf);
            map_del(ip6unfrag.m,key,NULL);
            STDERR("cannot add to time wheel\r\n");
            return NULL;
        }
        tdata->data=new_mbuf;
        //DBG_FLAGS;
        new_mbuf->next=NULL;
        new_mbuf->begin=m->offset;
        new_mbuf->offset=m->offset;
        new_mbuf->tail=new_mbuf->offset+payload_len-8+40;
        new_mbuf->priv_data=tdata;
        new_mbuf->priv_flags=frag_header->id;

    }else{
        new_mbuf=map_find(ip6unfrag.m,key,&is_found);
        // key不存在那么直接丢弃数据包
        if(NULL==new_mbuf){
            mbuf_put(m);
            return NULL;
        }
        // 修改尾部偏移,这里要减去扩展头部
        new_mbuf->tail+=payload_len-8;
    }

    new_mbuf->end=new_mbuf->tail;

    if(0!=frag_off){
        memcpy(new_mbuf->data+new_mbuf->offset+frag_off * 8 + 40 ,m->data+m->offset+48,payload_len-8);
    }else{
        memcpy(new_mbuf->data+new_mbuf->offset,m->data+m->offset,40);
        memcpy(new_mbuf->data+new_mbuf->offset+40,m->data+m->offset+48,payload_len-8);
        // 此处修改头部
        header=(struct netutil_ip6hdr *)(new_mbuf->data+new_mbuf->offset);
        header->next_header=frag_header->next_header;
    }

    mbuf_put(m);
    if(M!=0) return NULL;

    // 处理是最后一个分片的方法
    tdata=new_mbuf->priv_data;
    // 设置定时器为失效
    tdata->is_deleted=1;    
    // 删除映射记录
    map_del(ip6unfrag.m,key,NULL);

    // 重置私有参数
    new_mbuf->priv_data=NULL;
    new_mbuf->priv_flags=0;

    //DBG("%d\r\n",new_mbuf->tail-new_mbuf->offset);


    return new_mbuf;
}