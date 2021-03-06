#include<string.h>
#include<stdlib.h>

#include "ipunfrag.h"
#include "mbuf.h"

#include "../../../pywind/clib/timer.h"
#include "../../../pywind/clib/netutils.h"
#include "../../../pywind/clib/sysloop.h"
#include "../../../pywind/clib/debug.h"

static struct ipunfrag ipunfrag;
static int ipunfrag_is_initialized=0;
static struct time_wheel ipunfrag_time_wheel;
static struct sysloop *ipunfrag_sysloop;

static void ipunfrag_map_del_cb(void *data)
{
    struct mbuf *m=data;
    struct time_data *tdata=m->priv_data;
    
    tdata->is_deleted=1;
    mbuf_put(m);
}

static void ipunfrag_timeout_cb(void *data)
{
    char key[IPUNFRAG_KEYSIZE];
    struct mbuf *m=data;
    struct netutil_iphdr *header=(struct netutil_iphdr *)(m->data+m->offset);

    memcpy(&key[0],header->src_addr,4);
    memcpy(&key[4],header->dst_addr,4);
    memcpy(&key[8],(char *)(&(header->id)),2);

    map_del(ipunfrag.m,key,ipunfrag_map_del_cb);
}

static void ipunfrag_sysloop_cb(struct sysloop *loop)
{
    time_wheel_handle(&ipunfrag_time_wheel);
}

int ipunfrag_init(void)
{
    struct map *m;
    int rs=map_new(&m,IPUNFRAG_KEYSIZE);

    if(0!=rs){
        STDERR("cannot create map for ipunfrag\r\n");
        return -1;
    }

    // 这里的时间需要大于10s,因为系统IO阻塞时间为10s
    rs=time_wheel_new(&ipunfrag_time_wheel,60,1,ipunfrag_timeout_cb,4096);
    if(0!=rs){
        map_release(m,NULL);
        STDERR("cannot create timer\r\n");
        return -1;
    }

    ipunfrag_sysloop=sysloop_add(ipunfrag_sysloop_cb,NULL);
    if(NULL==ipunfrag_sysloop){
        time_wheel_release(&ipunfrag_time_wheel);
        map_release(m,NULL);
        STDERR("cannot add to sysloop\r\n");
        return -1;
    }

    bzero(&ipunfrag,sizeof(struct ipunfrag));

    ipunfrag.m=m;
    ipunfrag_is_initialized=1;

    return 0;
}

void ipunfrag_uninit(void)
{
    map_release(ipunfrag.m,ipunfrag_map_del_cb);
    time_wheel_release(&ipunfrag_time_wheel);

    ipunfrag_is_initialized=0;
}

struct mbuf *ipunfrag_add(struct mbuf *m)
{
    struct mbuf *new_mbuf;
    struct netutil_iphdr *header;
    int mf,rs,header_len;
    unsigned short frag_info,offset,tot_len;
    char key[10],is_found;
    struct time_data *tdata;

    if(!ipunfrag_is_initialized){
        mbuf_put(m);
        STDERR("please init ipunfrag\r\n");
        return NULL;
    }

    header=(struct netutil_iphdr *)(m->data+m->offset);
    header_len=(header->ver_and_ihl & 0x0f) * 4; 

    tot_len=ntohs(header->tot_len);

    frag_info=ntohs(header->frag_info);

    offset=frag_info & 0x1fff;
    mf=frag_info & 0x2000;
    
    memcpy(&key[0],header->src_addr,4);
    memcpy(&key[4],header->dst_addr,4);
    memcpy(&key[8],(char *)(&(header->id)),2);

    // 限制大小,避免缓冲区溢出
    if(offset * 8 > 0xff00){
        map_del(ipunfrag.m,key,ipunfrag_map_del_cb);
        mbuf_put(m);
        return NULL;
    }

    // 如果不是第一个分包检查key是否存在
    if(offset!=0){
        new_mbuf=map_find(ipunfrag.m,key,&is_found);
        // key不存在那么直接丢弃数据包
        if(NULL==new_mbuf){
            mbuf_put(m);
            return NULL;
        }
        // 修改尾部偏移
        new_mbuf->tail+=tot_len-header_len;
    }else{
        // 检查是否发送了重复的数据包,如果是重复的数据包那么直接丢弃
        new_mbuf=map_find(ipunfrag.m,key,&is_found);
        //DBG_FLAGS;
        if(NULL!=new_mbuf){
            mbuf_put(m);
            return NULL;
        }

        new_mbuf=mbuf_get();
        if(NULL==new_mbuf){
            STDERR("cannot get mbuf for ip ipunfrag\r\n");
            mbuf_put(m);
            return NULL;
        }

        rs=map_add(ipunfrag.m,key,new_mbuf);
        if(rs!=0){
            mbuf_put(new_mbuf);
            mbuf_put(m);
            STDERR("cannot to map\r\n");
            return NULL;
        }
        //DBG_FLAGS;
        tdata=time_wheel_add(&ipunfrag_time_wheel,new_mbuf,1);
        if(NULL==tdata){
            mbuf_put(m);
            mbuf_put(new_mbuf);
            map_del(ipunfrag.m,key,NULL);
            STDERR("cannot add to time wheel\r\n");
            return NULL;
        }
        tdata->data=new_mbuf;
        //DBG_FLAGS;
        new_mbuf->next=NULL;
        new_mbuf->begin=m->offset;
        new_mbuf->offset=m->offset;
        new_mbuf->tail=m->tail;
        new_mbuf->end=m->tail;
        new_mbuf->priv_data=tdata;
        new_mbuf->priv_flags=header_len;
        
    }

    new_mbuf->end=new_mbuf->tail;

    if(0!=offset) memcpy(new_mbuf->data+new_mbuf->offset+offset * 8 + new_mbuf->priv_flags,m->data+m->offset+header_len,tot_len-header_len);
    else memcpy(new_mbuf->data+new_mbuf->offset,m->data+m->offset,tot_len);

    mbuf_put(m);

    // 不是最后一个分包那么直接返回
    if(mf!=0) return NULL;

    // 处理是最后一个分片的方法
    tdata=new_mbuf->priv_data;
    // 设置定时器为失效
    tdata->is_deleted=1;    
    // 删除映射记录
    map_del(ipunfrag.m,key,NULL);

    // 重置私有参数
    new_mbuf->priv_data=NULL;
    new_mbuf->priv_flags=0;

    return new_mbuf;
}