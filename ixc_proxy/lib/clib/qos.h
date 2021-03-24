#ifndef QOS_H
#define QOS_H

#include "mbuf.h"

struct qos_slot{
    struct mbuf *mbuf_first;
    struct mbuf *mbuf_last;

    struct qos_slot *next;

    int slot;
    int is_used;
};

#define QOS_SLOT_NUM 1024

struct qos{
    struct qos_slot *slot_objs[QOS_SLOT_NUM];
    struct qos_slot *slot_head;
};


int qos_init(void);
void qos_uninit(void);

/// 把流量加入到QOS槽中
void qos_add(struct mbuf *m);

/// 自动弹出槽中的数据
void qos_pop(void);

/// 检查QOS中是否还有数据未被发送
// 如果已经发送完毕那么返回0,否则返回1
int qos_have_data(void);

#endif