#ifndef EV_H
#define EV_H

#include<sys/time.h>

/// 表示不需要任何事件
#define EV_NO 0
/// 表示读事件
#define EV_READ 1
/// 表示写事件
#define EV_WRITE 2
/// 表示退出事件
#define EV_EXIT 4

struct ev;

/// event callback function
// this function return is_error,there is not any error if zero,else it is error

typedef void (*ev_cb_func_t)(struct ev *);

struct ev{
    struct ev *next;
    ev_cb_func_t ev_cb_func;

    void *priv_data;
    int fd;
    // happend event
    int cur_ev;
    // Modified event
    int modified_ev;
    // the event if need delete
    int is_deleted;
};


#define EV_SET(ev_obj,priv,fileno,ev_code,cb_func) \
bzero(ev_obj,sizeof(struct ev));\
ev_obj->priv_data=priv;\
ev_obj->fd=fileno;\
ev_obj->modified_ev=ev_code;\
ev_obj->ev_cb_func=cb_func


int ev_init(void);
void ev_uninit(void);

struct ev *ev_new(void);
void ev_del(struct ev *e);

void ev_modify_io_wait(struct timeval *t);

void ev_loop(void);


#endif