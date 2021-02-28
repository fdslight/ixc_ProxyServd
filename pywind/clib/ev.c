#include<stdlib.h>
#include<string.h>
#include<sys/time.h>
#include<unistd.h>
#include<errno.h>

#include "debug.h"
#include "ev.h"
#include "sysloop.h"

static struct ev *ev_head=NULL;
static struct timeval ev_time;

static fd_set ev_readfds;
static fd_set ev_writefds;

static int ev_nfds=0;


static void ev_each(void)
{
    struct ev *del_head=NULL;
    struct ev *e=ev_head,*head=NULL,*t;
    int ev_read,ev_write;

    while(NULL!=e){
        t=e->next;
        if(e->is_deleted){
            e->next=del_head;
            del_head=e;
        }else{
            e->next=head;
            head=e;
        }
        e=t;
    }

    // 释放ev资源
    e=del_head;
    while(NULL!=e){
        t=e->next;
        e->cur_ev=EV_EXIT;
        e->ev_cb_func(e);
        free(e);
        e=t;
    }

    ev_nfds=0;
    // 进行事件初始化
    e=head;

    while(NULL!=e){
        ev_read=e->modified_ev & EV_READ;
        ev_write=e->modified_ev & EV_WRITE;

        if(ev_read && !FD_ISSET(e->fd,&ev_readfds)) FD_SET(e->fd,&ev_readfds);
        if(ev_write && !FD_ISSET(e->fd,&ev_writefds)) FD_SET(e->fd,&ev_writefds);

        if(!ev_read && FD_ISSET(e->fd,&ev_readfds)) FD_CLR(e->fd,&ev_readfds);
        if(!ev_write && FD_ISSET(e->fd,&ev_writefds)) FD_CLR(e->fd,&ev_writefds);

        if(ev_read || ev_write){
            if(e->fd>ev_nfds) ev_nfds=e->fd;
        }

        e=e->next;
    }

    ev_nfds+=1;
}

static void ev_handle(void)
{
    struct ev *e=ev_head;

    // read
    while(NULL!=e){
        if(FD_ISSET(e->fd,&ev_readfds)) {
            if(e->is_deleted){
                e=e->next;
                continue;
            }
            e->cur_ev=EV_READ;
            e->ev_cb_func(e);
        }
        e=e->next;
    }

    // write
    e=ev_head;
    while(NULL!=e){
        if(FD_ISSET(e->fd,&ev_writefds)) {
            if(e->is_deleted){
                e=e->next;
                continue;
            }
            e->cur_ev=EV_WRITE;
            e->ev_cb_func(e);
        }
        e=e->next;
    }

}

int ev_init(void)
{
    FD_ZERO(&ev_readfds);
    FD_ZERO(&ev_writefds);

    ev_time.tv_sec=10;
    ev_time.tv_usec=0;

    return 0;
}

void ev_uninit(void)
{
    struct ev *e=ev_head,*t;

    while(NULL!=e){
        e->cur_ev=EV_EXIT;
        e->ev_cb_func(e);
        t=e->next;
        free(e);
        e=t;
    }
}

struct ev *ev_new(void)
{
    struct ev *e=malloc(sizeof(struct ev));

    if(NULL==e){
        STDERR("no memory for malloc struct ev\r\n");
        return NULL;
    }

    bzero(e,sizeof(struct ev));

    e->next=ev_head;
    ev_head=e;
    
    return e;
}

void ev_del(struct ev *e)
{
    e->is_deleted=1;
}

void ev_modify_io_wait(struct timeval *t)
{
    memcpy(&ev_time,t,sizeof(struct timeval));
}

void ev_loop(void)
{
    int rs;

__LOOP:
    for(;;){
        ev_each();
        rs=select(ev_nfds,&ev_readfds,&ev_writefds,NULL,&ev_time);

        if(0==rs){
            sysloop_do();
            continue;
        }
        if(rs>0){
            ev_handle();
            sysloop_do();
            continue;
        }
        break;
    }

    switch(errno){
        case EBADF:
            STDERR("select EBADF error\r\n");
            break;
        case EFAULT:
            STDERR("select EFAULT error\r\n");
            break;
        case EINTR:
            goto __LOOP;
            break;
        case EINVAL:
            STDERR("select EINVAL error\r\n");
            break;
        default:
            STDERR("select unkown error\r\n");
            break;
    }
}

