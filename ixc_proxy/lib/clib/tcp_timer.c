#include<sys/time.h>
#include<string.h>

#include "tcp_timer.h"
#include "debug.h"

static struct tcp_timer tcp_timer;

/// 根据超时获取对应的tick
static struct tcp_timer_tick *tcp_timer_get_tick(time_t timeout_ms)
{
    int tot=timeout_ms / tcp_timer.tick_timeout,r=timeout_ms % tcp_timer.tick_timeout;
    int idx;
    struct tcp_timer_tick *result=NULL;

    if(r>0) tot+=1;
    if(tot>0) tot-=1;

    idx=tot+tcp_timer.cur_idx_no;
    if(idx>=tcp_timer.tick_num) idx=idx-tcp_timer.tick_num;

    //DBG("Index old:%d new:%d\r\n",tcp_timer.cur_idx_no,idx);

    result=tcp_timer.tick_idx[idx];

    return result;
}

int tcp_timer_init(time_t wheel_max,time_t tick_timeout)
{
    int tot=wheel_max * 1000 / tick_timeout;
    struct tcp_timer_tick *tick,*last=NULL;

    if(tot<1){
        STDERR("wrong argument value\r\n");
        return -1;
    }

    bzero(&tcp_timer,sizeof(struct tcp_timer));

    tcp_timer.tick_idx=malloc(sizeof(NULL)*(tot+1));
    if(NULL==tcp_timer.tick_idx){
        STDERR("no memory for tick index\r\n");
        return -1;
    }

    // 这里多加1避免索引溢出
    bzero(tcp_timer.tick_idx,sizeof(NULL) * (tot+1));

    for(int n=0;n<tot;n++){
        tick=malloc(sizeof(struct tcp_timer_tick));
        if(NULL==tick){
            tcp_timer_uninit();
            STDERR("no memory for struct tcp_timer_tick\r\n");
            return -1;
        }
        bzero(tick,sizeof(struct tcp_timer_tick));
        if(NULL==tcp_timer.tick_head) {
            tcp_timer.tick_head=tick;
        }else{
            last->next=tick;
        }
        last=tick;
        tcp_timer.tick_idx[n]=tick;
        tick->idx_no=n;
    }

    last->next=tcp_timer.tick_head;

    gettimeofday(&(tcp_timer.up_time),NULL);
    tcp_timer.tick_timeout=tick_timeout;
    tcp_timer.tick_num=tot;
    tcp_timer.timeout_max=wheel_max;

    return 0;
}

void tcp_timer_uninit(void)
{
    struct tcp_timer_tick *tick,*t_tick;
    struct tcp_timer_node *node,*t_node;

    for(int i=0;i<tcp_timer.tick_num;i++){
        tick=tcp_timer.tick_idx[i];
        
        node=tick->head;
        while(NULL!=node){
            t_node=node->next;
            free(node);
            node=t_node;
        }
        t_tick=tick->next;
        tick=t_tick;
    }

    free(tcp_timer.tick_idx);
}

struct tcp_timer_node *tcp_timer_add(time_t timeout_ms,tcp_timer_cb_t fn,void *data)
{
    struct tcp_timer_node *node;
    struct tcp_timer_tick *tick;

    node=malloc(sizeof(struct tcp_timer_node));

    if(NULL==node){
        STDERR("no memory for struct tcp_timer_add\r\n");
        return NULL;
    }

    bzero(node,sizeof(struct tcp_timer_node));

    tick=tcp_timer_get_tick(timeout_ms);
    
    node->next=tick->head;
    tick->head=node;

    node->is_valid=1;
    node->fn=fn;
    node->tick=tick;
    node->data=data;

    return node;
}

void tcp_timer_update(struct tcp_timer_node *node,time_t timeout_ms)
{
    struct tcp_timer_tick *tick=node->tick;

    if(timeout_ms/1000 > tcp_timer.timeout_max){
        STDERR("cannot update time,the value is too large %ld\r\n",timeout_ms);
        return;
    }

    
    node->timeout_flags=0;
    tick=tcp_timer_get_tick(timeout_ms);

    node->next=tick->head;
    tick->head=node;
}

void tcp_timer_del(struct tcp_timer_node *node)
{
    // 如果设置了超时标志,那么释放内存
    if(node->timeout_flags){
        free(node);
    }else{
        // 如果未超时那么设置为无效
        node->is_valid=1;
    }
}

void tcp_timer_do(void)
{
    struct timeval tv;
    int ms,tot;
    struct tcp_timer_tick *tick=tcp_timer.tick_head;
    struct tcp_timer_node *node,*t_node,*head=NULL;

    gettimeofday(&tv,NULL);

    ms=tcp_timer_interval_calc(&(tcp_timer.up_time),&tv);
    tot=ms / tcp_timer.tick_timeout;

    for(int n=0;n<tot;n++){
        node=tick->head;
        while(NULL!=node){
            if(!node->is_valid){
                t_node=node->next;
                free(node);
                node=t_node;
            }else{
                node->timeout_flags=1;
                // 这里可能在回调函数出现删除node情况,此处需要提前指向下一个node
                t_node=node->next;

                node->next=head;
                head=node;

                node=t_node;
            }
        }
        //DBG_FLAGS;
        // 清空node head,注意回收内存
        tick->head=NULL;
        tick=tick->next;
    }

    // 此处更新tick head，以便超时函数里能够调用tcp_timer_update
    // 另外注意需要判断时间间隔是否低于单个tick时间,如果不加入判断那么tick永远无法向前移动
    if(NULL!=head){
        tcp_timer.tick_head=tick;
        tcp_timer.cur_idx_no=tick->idx_no;
        memcpy(&tcp_timer.up_time,&tv,sizeof(struct timeval));
    }

    node=head;
    while(NULL!=node){
        t_node=node->next;
        node->fn(node->data);
        node=t_node;
    }
}

time_t tcp_timer_interval_calc(struct timeval *begin,struct timeval *end)
{
    int usec=end->tv_usec-begin->tv_usec;
    time_t sec=end->tv_sec-begin->tv_sec;
    time_t r;

    // 如果微妙差值小于0,那么从秒这里借位
    if(usec<0){
        sec--;
        usec=usec+1000000;
    }

    r=sec * 1000 + usec/1000;
    
    return r;
}
