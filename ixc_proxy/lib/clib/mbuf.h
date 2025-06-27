#ifndef IXC_MBUF_H
#define IXC_MBUF_H

#include<sys/types.h>

struct mbuf{
    struct mbuf *next;
    void *priv_data;
    int priv_flags;
#define MBUF_BEGIN 256
    int begin;
    int offset;
    int tail;
    int end; 
#define MBUF_FROM_LAN 0
#define MBUF_FROM_WAN 1
    int from;
    int is_ipv6;
    unsigned char id[16];
#define MBUF_DATA_MAX_SIZE 0x10800
    unsigned char data[MBUF_DATA_MAX_SIZE];
};

int mbuf_init(size_t pre_alloc_size);
void mbuf_uninit(void);

struct mbuf *mbuf_get(void);
void mbuf_put(struct mbuf *m);
size_t mbuf_free_num_get(void);

#endif