#ifndef TCP_TIMER_H
#define TCP_TIMER_H

#include<sys/types.h>

/// TCP定时器tick时间,单位是毫秒
#define TCP_TIMER_TICK_INTERVAL 10

struct tcp_timer_node;
typedef void (*tcp_timer_cb_t)(void *data);
typedef unsigned long long tcp_time_t;

struct tcp_timer_tick;

/// TCP timer节点
struct tcp_timer_node{
    struct tcp_timer_node *next;
    // 所指向的tick
    struct tcp_timer_tick *tick;
    // 指向的回调函数
    tcp_timer_cb_t fn;
    // 指向的TCP会话
    void *data;
    // 是否有效,如果为0表示该会话已经删除
    int is_valid;
    // timeout标志,如果非0表示超时,0表示未超时
    int timeout_flags;
};

/// TCP timer tick
struct tcp_timer_tick{
    struct tcp_timer_tick *next;
    struct tcp_timer_node *head;
    // 对应的索引号
    int idx_no;
};

struct tcp_timer{
    struct tcp_timer_tick *next;
    struct tcp_timer_tick *tick_head;
    // tick索引
    struct tcp_timer_tick **tick_idx;
    // 更新时间
    struct timeval up_time;
    time_t tick_timeout;
    // 最大超时时间
    time_t timeout_max;
    int tick_num;
    // 当前索引号
    int cur_idx_no;
};

/// 
// wheel_max表示最大超时,单位是秒
// tick_timeout表示单个tick的超时时间,单位是毫秒
int tcp_timer_init(time_t wheel_max,time_t tick_timeout);
void tcp_timer_uninit(void);

struct tcp_timer_node *tcp_timer_add(time_t timeout_ms,tcp_timer_cb_t fn,void *data);
void tcp_timer_update(struct tcp_timer_node *node,time_t timeout_ms);

void tcp_timer_del(struct tcp_timer_node *node);
void tcp_timer_do(void);

/// 时间间隔计算
// begin表示开始时间
// end 表示结束时间
// return:返回时间为毫秒的差值
time_t tcp_timer_interval_calc(struct timeval *begin,struct timeval *end);

#endif