#include<stdlib.h>
#include<string.h>
#include<time.h>

#include "timer.h"
#include "debug.h"

/// 从预先分配的内存池中获取time_data
static struct time_data *time_data_get(struct time_wheel *time_wheel)
{
    struct time_data *tdata;

    if(NULL==time_wheel->empty_data_head){
        tdata=malloc(sizeof(struct time_data));
        if(NULL==tdata) return NULL;

        bzero(tdata,sizeof(struct time_data));
        time_wheel->cur_data_num+=1;
    }else{
        tdata=time_wheel->empty_data_head;
        time_wheel->empty_data_head=tdata->next;
        tdata->next=NULL;
    }

    tdata->is_deleted=0;

    return tdata;
}

/// 放回time_data
static void time_data_put(struct time_wheel *time_wheel,struct time_data *data)
{
    if(NULL==data) return;

    if(time_wheel->cur_data_num>time_wheel->pre_alloc_data_num){
        free(data);
        time_wheel->cur_data_num-=1;
        return;
    }

    data->next=time_wheel->empty_data_head;
    time_wheel->empty_data_head=data;
}

static void time_wheel_timeout(struct time_wheel *time_wheel,struct time_data *first)
{
    struct time_data *tdata=first,*t;

    //DBG_FLAGS;
    while(NULL!=tdata){
        if(!tdata->is_deleted) time_wheel->timeout_fn(tdata->data);

        tdata->is_deleted=1;
        t=tdata->next;
        // 回收data数据结构
        time_data_put(time_wheel,tdata);
        tdata=t;
    }
}

static struct time_tick *time_wheel_tick_get(struct time_wheel *time_wheel,time_t timeout)
{
    int n=timeout/time_wheel->every_tick_timeout;
    struct time_tick *tick=time_wheel->cur_tick;

    if(n<1) n=1;
    n-=1;

    n=tick->idx_no+n;

    return time_wheel->tick_idx[n];
}


int time_wheel_new(struct time_wheel *time_wheel,unsigned int tick_size,time_t every_tick_timeout,time_timeout_fn_t timeout_fn,unsigned int pre_alloc_data_num)
{
    struct time_tick *tick,*last=NULL;
    struct time_data *tdata;

    // 检查参数是否合法,时间不能小于等于0
    if(tick_size * every_tick_timeout <0){
        STDERR("wrong argument value\r\n");
        return -1;
    }

    bzero(time_wheel,sizeof(struct time_wheel));

    time_wheel->tick_idx=malloc(sizeof(NULL)*(tick_size+1));
    if(NULL==time_wheel->tick_idx){
        STDERR("cannot malloc tick index\r\n");
        return -1;
    }

    bzero(time_wheel->tick_idx,sizeof(NULL)*(tick_size+1));
   
    // 这里tick数目多一个是考虑临界情况
    for(int n=0;n<tick_size;n++){
        tick=malloc(sizeof(struct time_tick));
        if(NULL==tick){
            time_wheel_release(time_wheel);
            STDERR("no memory for malloc struct time_tick\r\n");
            return -1;
        }

        bzero(tick,sizeof(struct time_tick));

        if(NULL==last) time_wheel->cur_tick=tick;
        else last->next=tick;

        last=tick;
        tick->idx_no=n;
        time_wheel->tick_idx[n]=tick;
        time_wheel->tick_size+=1;
    }

    last->next=time_wheel->cur_tick;

    for(int n=0;n<pre_alloc_data_num;n++){
        tdata=malloc(sizeof(struct time_data));
        if(NULL==tdata){
            time_wheel_release(time_wheel);
            STDERR("no memory for malloc struct time_data\r\n");
            return -1;
        }

        bzero(tdata,sizeof(struct time_data));

        tdata->next=time_wheel->empty_data_head;
        time_wheel->empty_data_head=tdata;
    }

    time_wheel->old_time=time(NULL);
    time_wheel->every_tick_timeout=every_tick_timeout;
    time_wheel->timeout_fn=timeout_fn;
    time_wheel->pre_alloc_data_num=pre_alloc_data_num;
    time_wheel->cur_data_num=pre_alloc_data_num;

    return 0;
}

void time_wheel_release(struct time_wheel *time_wheel)
{
    struct time_tick *tick=time_wheel->cur_tick,*t;
    struct time_data *tdata=NULL,*tmp;

    for(int n=0;n<time_wheel->tick_size;n++){
        t=tick->next;
        time_wheel_timeout(time_wheel,tick->time_data);
        free(tick);
        tick=t;
    }
    // 回收time_data
    tdata=time_wheel->empty_data_head;
    while(NULL!=tdata){
        tmp=tdata->next;
        free(tdata);
        tdata=tmp;
    }

    if(NULL!=time_wheel->tick_idx) free(time_wheel->tick_idx);

    bzero(time_wheel,sizeof(struct time_wheel));
}


struct time_data *time_wheel_add(struct time_wheel *time_wheel,void *data,time_t timeout)
{
    struct time_data *tdata;
    struct time_tick *tick=NULL;

    if(timeout<0){
        STDERR("the timeout must be more than zero\r\n");
        return NULL;
    }

    tick=time_wheel_tick_get(time_wheel,timeout);

    tdata=time_data_get(time_wheel);

    if(NULL==tdata){
        STDERR("no memory for struct time_data\r\n");
        return NULL;
    }

    bzero(tdata,sizeof(struct time_data));
    
    tdata->next=tick->time_data;
    tdata->data=data;
    tick->time_data=tdata;

    return tdata;
}

void time_wheel_handle(struct time_wheel *time_wheel)
{
    unsigned int tick_n;
    time_t now=time(NULL);
    time_t v=now-time_wheel->old_time;
    struct time_tick *tick=time_wheel->cur_tick,*old_tick;

    tick_n=v/time_wheel->every_tick_timeout;

    old_tick=tick;
    //DBG("tick %d\r\n",tick_n);

    // 首先挪动tick,以便回调函数中能添加基于当前时间的超时
    for(int n=0;n<=tick_n;n++) tick=tick->next;

    if(tick_n>0) {
        time_wheel->old_time=now;
        time_wheel->cur_tick=tick;
    }

    tick=old_tick;
    for(int n=0;n<tick_n;n++){
        //DBG_FLAGS;
        time_wheel_timeout(time_wheel,tick->time_data);
        //DBG_FLAGS;
        tick->time_data=NULL;
        tick=tick->next;
    }

}