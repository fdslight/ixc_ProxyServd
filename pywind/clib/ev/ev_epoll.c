#include<unistd.h>

#include<sys/epoll.h>
#include<errno.h>

#include "ev.h"
#include "ev_ext.h"

#include "../debug.h"

static struct epoll_event ev_epoll_events[EV_EV_MAX];
static int ev_epoll_fileno=-1;

static int ev_epoll_add_read(struct ev *ev)
{
    struct epoll_event epoll_event;
    
    epoll_event.data.fd=ev->fileno;
    epoll_event.events=EPOLLIN;

    return epoll_ctl(ev_epoll_fileno,EPOLL_CTL_MOD,ev->fileno,&epoll_event);
}

static int ev_epoll_add_write(struct ev *ev)
{
    struct epoll_event epoll_event;
    
    epoll_event.data.fd=ev->fileno;
    epoll_event.events=EPOLLOUT;

    return epoll_ctl(ev_epoll_fileno,EPOLL_CTL_MOD,ev->fileno,&epoll_event);
}

static int ev_epoll_del_read(struct ev *ev)
{
    struct epoll_event epoll_event;
    
    epoll_event.data.fd=ev->fileno;
    epoll_event.events=EPOLLIN;

    return epoll_ctl(ev_epoll_fileno,EPOLL_CTL_DEL,ev->fileno,&epoll_event);
}

static int ev_epoll_del_write(struct ev *ev)
{
    struct epoll_event epoll_event;
    
    epoll_event.data.fd=ev->fileno;
    epoll_event.events=EPOLLOUT;

    return epoll_ctl(ev_epoll_fileno,EPOLL_CTL_DEL,ev->fileno,&epoll_event);
}

static void ev_epoll_handle_events(struct ev_set *ev_set,int nfds)
{
    struct epoll_event *event;
    struct ev *ev;
    int fd,readable,writable;

    for(int n=0;n<nfds;n++){
        event=&ev_epoll_events[n];
        fd=event->data.fd;

        readable=event->events & EPOLLIN;
        writable=event->events & EPOLLOUT;

        ev=ev_get(ev_set,fd);

        if(NULL==ev){
            STDERR("cannot get ev for fileno %d\r\n",fd);
            continue;
        }

        if(readable && !ev->is_deleted && NULL!=ev->readable_fn){
            ev->readable_fn(ev);
        }

        if(writable && !ev->is_deleted && NULL!=ev->writable_fn){
            ev->writable_fn(ev);
        }

    }

}

static int ev_epoll_ioloop(struct ev_set *ev_set)
{
    // 注意epoll的超时事件为毫秒,换算成秒要乘以1000
    int nfds=epoll_wait(ev_epoll_fileno,ev_epoll_events,EV_EV_MAX,ev_set->wait_timeout*1000);
    
    ev_epoll_handle_events(ev_set,nfds);

    return 0;
}

static int ev_epoll_create(struct ev *ev)
{
    struct epoll_event epoll_event;
    
    epoll_event.data.fd=ev->fileno;
    epoll_event.events=0;

    return epoll_ctl(ev_epoll_fileno,EPOLL_CTL_ADD,ev->fileno,&epoll_event);
}

static void ev_epoll_delete(struct ev *ev)
{
    struct epoll_event epoll_event;
    
    epoll_event.data.fd=ev->fileno;
    epoll_event.events=0;

    epoll_ctl(ev_epoll_fileno,EPOLL_CTL_DEL,ev->fileno,&epoll_event);
}

int ev_ext_init(struct ev_set *ev_set)
{
    ev_epoll_fileno=epoll_create(256);
    if(ev_epoll_fileno<0){
        STDERR("cannot create epoll\r\n");
        return -1;
    }

    ev_set->ev_create_fn=ev_epoll_create;
	ev_set->ev_delete_fn=ev_epoll_delete;
	ev_set->ioloop_fn=ev_epoll_ioloop;
	
	ev_set->add_read_ev_fn=ev_epoll_add_read;
	ev_set->add_write_ev_fn=ev_epoll_add_write;
	ev_set->del_read_ev_fn=ev_epoll_del_read;
	ev_set->del_write_ev_fn=ev_epoll_del_write;

    return 0;
}

void ev_ext_uninit(struct ev_set *ev_set)
{
    close(ev_epoll_fileno);
}