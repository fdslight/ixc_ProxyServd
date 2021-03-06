#include<stdlib.h>

#include "mbuf.h"
#include "../../../pywind/clib/debug.h"

/// 空的mbuf
static struct mbuf *mbuf_empty_head=NULL;
/// 空的mbuf数目
static size_t mbuf_free_num=0;
/// 已经分配的mbuf数目
static size_t mbuf_used_num=0;
/// 预先分配的mbuf数目
static size_t mbuf_pre_alloc_num=0;
/// 是否初始化
static int mbuf_is_initialized=0;

int mbuf_init(size_t pre_alloc_num)
{
    struct mbuf *m=NULL;
    mbuf_is_initialized=1;

    for(size_t n=0;n<pre_alloc_num;n++){
        m=malloc(sizeof(struct mbuf));
        if(NULL==m){
            STDERR("no memory for pre alloc struct mbuf\r\n");
            mbuf_uninit();
            return -1;
        }
 
        m->next=mbuf_empty_head;
        mbuf_empty_head=m;
    }

    mbuf_used_num=pre_alloc_num;
    mbuf_pre_alloc_num=pre_alloc_num;
    mbuf_free_num=pre_alloc_num;

    return 0;
}

void mbuf_uninit(void)
{
    struct mbuf *m=mbuf_empty_head,*t;

    if(!mbuf_is_initialized){
        STDERR("no initialized\r\n");
        return;
    }

    while(NULL!=m){
        t=m->next;
        free(m);
        m=t;
    }
}

struct mbuf *mbuf_get(void)
{
    struct mbuf *m;

    if(!mbuf_is_initialized){
        STDERR("no initialized\r\n");
        return NULL;
    }

    if(NULL!=mbuf_empty_head){
        m=mbuf_empty_head;
        mbuf_empty_head=m->next;

        m->next=NULL;
        mbuf_free_num-=1;

        return m;
    }

    m=malloc(sizeof(struct mbuf));
    if(NULL==m){
        STDERR("no memory for struct mbuf\r\n");
        return NULL;
    }

    STDERR("get mbuf from malloc\r\n");

    m->next=NULL;
    m->priv_data=NULL;
    m->priv_flags=0;

    mbuf_used_num+=1;

    return m;
}

void mbuf_put(struct mbuf *m)
{
    if(!mbuf_is_initialized){
        STDERR("no initialized\r\n");
        return;
    }

    if(NULL==m) return;

    if(mbuf_used_num > mbuf_pre_alloc_num){
        free(m);
        mbuf_used_num-=1;

        return;
    }

    m->next=mbuf_empty_head;
    mbuf_empty_head=m;
    mbuf_free_num+=1;
}

inline
size_t mbuf_free_num_get(void)
{
    return mbuf_free_num; 
}