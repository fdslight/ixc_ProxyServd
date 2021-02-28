/** 实现时间轮算法,该时间轮为一层 **/
#ifndef TIMER_H
#define TIMER_H

#include<sys/types.h>

/// 超时回调函数
typedef void(*time_timeout_fn_t)(void *data,int is_deleted);

/// 数据存储对象
struct time_data{
    // 下一个存储对象
    struct time_data *next;
    // 存储内容
    void *data;
    // 内容是否已经被删除,如果为0表示未删除,超时之后将会调用超时函数,否则不用调用超时函数
    int is_deleted;
};

/// 每个tick对应的数据结构
struct time_tick{
    // 指向下一个tick
    struct time_tick *next;
    struct time_data *time_data;
};

/// 时间轮对象
struct time_wheel{
    // 当前tick
    struct time_tick *cur_tick;
    struct time_data *empty_data_head;
    time_timeout_fn_t timeout_fn;
    // 每个tick持续的时间
    time_t every_tick_timeout;
    // 上一次的时间
    time_t old_time;
    // 总共的tick格数
    unsigned int tick_size;
    // 当前保存的data数目
    unsigned int cur_data_num;
    // 预先分配的data数目
    unsigned int pre_alloc_data_num;
};

int time_wheel_new(struct time_wheel *time_wheel,unsigned int tick_size,time_t every_tick_timeout,time_timeout_fn_t timeout_fn,unsigned int pre_alloc_data_num);
void time_wheel_release(struct time_wheel *time_wheel);
/// 函数失败返回NULL
struct time_data *time_wheel_add(struct time_wheel *time_wheel,void *data,time_t timeout);

/// 此函数需要循环调用,以便让时间能够走动
void time_wheel_handle(struct time_wheel *time_wheel);

#endif