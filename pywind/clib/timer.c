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

static void time_wheel_timeout(struct time_wheel *time_wheel,struct time_data *first,int is_deleted)
{
    struct time_data *tdata=first,*t;

    while(NULL!=tdata){
        if(!tdata->is_deleted) time_wheel->timeout_fn(tdata->data,is_deleted);
        t=tdata->next;
        // 回收data数据结构
        time_data_put(time_wheel,tdata);
        tdata=t;
    }
}

int time_wheel_new(struct time_wheel *time_wheel,unsigned int tick_size,time_t every_tick_timeout,time_timeout_fn_t timeout_fn,unsigned int pre_alloc_data_num)
{
    struct time_tick *tick;
    struct time_data *tdata;

    // 检查参数是否合法,时间不能小于等于0
    if(tick_size * every_tick_timeout <0){
        STDERR("wrong argument value\r\n");
        return -1;
    }

    bzero(time_wheel,sizeof(struct time_wheel));
    
    // 这里tick数目多一个是考虑临界情况
    for(int n=0;n<tick_size+1;n++){
        tick=malloc(sizeof(struct time_tick));
        if(NULL==tick){
            time_wheel_release(time_wheel);
            STDERR("no memory for malloc struct time_tick\r\n");
            return -1;
        }

        time_wheel->tick_size+=1;

        bzero(tick,sizeof(struct time_tick));
        tick->next=time_wheel->cur_tick;
        time_wheel->cur_tick=tick;
    }

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
        time_wheel_timeout(time_wheel,tick->time_data,0);
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

    bzero(time_wheel,sizeof(struct time_wheel));
}


struct time_data *time_wheel_add(struct time_wheel *time_wheel,void *data,time_t timeout)
{
    struct time_data *tdata;
    struct time_tick *tick=time_wheel->cur_tick;
    unsigned int tick_n;

    if(timeout<0){
        STDERR("the timeout must be more than zero\r\n");
        return NULL;
    }

    // 因为之前tick_size增加了1,所以这里需要减去1
    if(timeout>(time_wheel->tick_size-1) * time_wheel->every_tick_timeout){
        STDERR("the value of timeout out of range\r\n");
        return NULL;
    }

    // 计算出需要移动的格数
    tick_n=timeout / time_wheel->every_tick_timeout;
    // 这里的时间必须大于或者等于一个tick的值
    if(tick_n<1){
        STDERR("the value of timeout is too small\r\n");
        return NULL;
    }

    tdata=time_data_get(time_wheel);
    if(NULL==tdata){
        STDERR("no memory for struct time_data\r\n");
        return NULL;
    }

    bzero(tdata,sizeof(struct time_data));
    
    // 找到要插入的tick位置
    for(int n=0;n<tick_n-1;n++) tick=tick->next;
    
    tdata->next=tick->time_data;
    tick->time_data=tdata;

    return tdata;
}

void time_wheel_handle(struct time_wheel *time_wheel)
{
    unsigned int tick_n;
    time_t now=time(NULL);
    time_t v=now-time_wheel->old_time;
    struct time_tick *tick=time_wheel->cur_tick;

    // 时间倒流的情况处理,该情况会发生在系统时间过快调整时间导致时间倒流
    if(v<0) tick_n=time_wheel->tick_size;
    else tick_n=v / time_wheel->every_tick_timeout;

    for(int n=0;n<tick_n;n++){
        time_wheel_timeout(time_wheel,tick->time_data,0);
        tick=tick->next;
    }
}