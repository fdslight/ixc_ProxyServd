#include<sys/event.h>
#include<unistd.h>

#include "ev.h"
#include "ev_ext.h"

#include "../debug.h"

static int ev_kqueue=0;
static struct kevent ev_kqueue_changelist[EV_EV_MAX];
static struct kevent ev_kqueue_evlist[EV_EV_MAX];
/// 改变的事件数目
static int ev_kqueue_change_count=0;

static int ev_kqueue_add_read(struct ev *ev)
{
    struct kevent *kevent;
    
    if(ev_kqueue_change_count==EV_EV_MAX){
        STDERR("changelist too small\r\n");
        return -1;
    }

    kevent=&ev_kqueue_changelist[ev_kqueue_change_count];

    kevent->ident=ev->fileno;
    kevent->filter=EVFILT_READ;
    kevent->flags=EV_ADD | EV_ENABLE;
    kevent->fflags=0;
    kevent->data=0;
    kevent->udata=ev;

    ev_kqueue_change_count++;
    return 0;
}

static int ev_kqueue_add_write(struct ev *ev)
{
    struct kevent *kevent;

    if(ev_kqueue_change_count==EV_EV_MAX){
        STDERR("changelist too small\r\n");
        return -1;
    }

    kevent=&ev_kqueue_changelist[ev_kqueue_change_count];

    kevent->ident=ev->fileno;
    kevent->filter=EVFILT_WRITE;
    kevent->flags=EV_ADD | EV_ENABLE;
    kevent->fflags=0;
    kevent->data=0;
    kevent->udata=ev;

    ev_kqueue_change_count++;
   
    return 0;
}

static int ev_kqueue_del_read(struct ev *ev)
{
    struct kevent *kevent;

    if(ev_kqueue_change_count==EV_EV_MAX){
        STDERR("changelist too small\r\n");
        return -1;
    }

    kevent=&ev_kqueue_changelist[ev_kqueue_change_count];
    kevent->ident=ev->fileno;
    kevent->filter=EVFILT_READ;
    kevent->flags=EV_ADD | EV_DELETE;
    kevent->fflags=0;
    kevent->data=0;
    kevent->udata=ev;

    ev_kqueue_change_count++;
 
    return 0;
}

static int ev_kqueue_del_write(struct ev *ev)
{
    struct kevent *kevent;

    if(ev_kqueue_change_count==EV_EV_MAX){
        STDERR("changelist too small\r\n");
        return -1;
    }

    kevent=&ev_kqueue_changelist[ev_kqueue_change_count];
    kevent->ident=ev->fileno;
    kevent->filter=EVFILT_WRITE;
    kevent->flags=EV_ADD | EV_DELETE;
    kevent->fflags=0;
    kevent->data=0;
    kevent->udata=ev;

    ev_kqueue_change_count++;
    
    return 0;
}

static void ev_kqueue_handle_events(struct ev_set *ev_set,struct kevent *events,int nevents)
{
    struct kevent *kevent;
    int readable,writable;
    struct ev *ev;
    short filter;

    ev_kqueue_change_count=0;

    for(int n=0;n<nevents;n++){
        kevent=&(events[n]);
        //ident=kevent->ident;
        ev=kevent->udata;
        filter=kevent->filter;

        readable=filter & EVFILT_READ;
        writable=filter & EVFILT_WRITE;

        if(readable && !ev->is_deleted && NULL!=ev->readable_fn){
            ev->readable_fn(ev);
        }

        if(writable && !ev->is_deleted && NULL!=ev->writable_fn){
            ev->writable_fn(ev);
        }
    }
}

static int ev_kqueue_ioloop(struct ev_set *ev_set)
{
    struct timespec timespec;
    int rs;

    timespec.tv_sec=ev_set->wait_timeout;
    timespec.tv_nsec=0;
    rs=kevent(ev_kqueue,ev_kqueue_changelist,ev_kqueue_change_count,ev_kqueue_evlist,EV_EV_MAX,&timespec);

    ev_kqueue_handle_events(ev_set,ev_kqueue_evlist,rs);

    return 0;
}

static int ev_kqueue_create(struct ev *ev)
{
	return 0;
}

static void ev_kqueue_delete(struct ev *ev)
{
}

int ev_ext_init(struct ev_set *ev_set)
{
    ev_kqueue=kqueue();

    if(ev_kqueue<0){
        STDERR("cannot kqueue\r\n");
        return -1;
    }

    ev_set->ev_create_fn=ev_kqueue_create;
    ev_set->ev_delete_fn=ev_kqueue_delete;
    ev_set->ioloop_fn=ev_kqueue_ioloop;

    ev_set->add_read_ev_fn=ev_kqueue_add_read;
    ev_set->add_write_ev_fn=ev_kqueue_add_write;
    ev_set->del_read_ev_fn=ev_kqueue_del_read;
    ev_set->del_write_ev_fn=ev_kqueue_del_write;

    return 0;
}

void ev_ext_uninit(struct ev_set *ev_set)
{
    close(ev_kqueue);
}