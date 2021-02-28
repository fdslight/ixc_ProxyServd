
#include<stdlib.h>
#include<stdio.h>
#include<string.h>

#include "sysloop.h"

#include "debug.h"

static struct sysloop *sysloop_head=NULL;

int sysloop_init(void)
{
    return 0;
}

void sysloop_uninit(void)
{
    struct sysloop *sysloop=sysloop_head,*t;

    while(NULL!=sysloop){
        t=sysloop->next;
        free(sysloop);
        sysloop=t;
    }

    sysloop_head=NULL;
}

struct sysloop *sysloop_add(sysloop_fn_cb_t cb_fb,void *data)
{
    struct sysloop *loop;
    
    loop=malloc(sizeof(struct sysloop));
    if(NULL==loop){
        STDERR("no memory for struct sysloop\r\n");
        return NULL;
    }

    bzero(loop,sizeof(struct sysloop));

    loop->next=sysloop_head;
    if(NULL!=sysloop_head) sysloop_head->prev=loop;
    sysloop_head=loop;
    
    loop->data=data;
    loop->fn_cb=cb_fb;

    return loop;
}

void sysloop_del(struct sysloop *sysloop)
{
    if(NULL==sysloop) return;

    if(NULL==sysloop->prev){
        sysloop_head=sysloop->next;
        free(sysloop);
        return;
    }

    if(NULL==sysloop->next){
        sysloop->prev->next=NULL;
        free(sysloop);
        return;
    }

    sysloop->prev->next=sysloop->next;
    free(sysloop);
}

void sysloop_do(void)
{
    struct sysloop *sysloop=sysloop_head;

    while(NULL!=sysloop){
        sysloop->fn_cb(sysloop);
        sysloop=sysloop->next;
    }
}
