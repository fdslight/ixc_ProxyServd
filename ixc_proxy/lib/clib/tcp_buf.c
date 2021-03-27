#include "tcp_buf.h"
#include "debug.h"

/// 缓冲区指针后移动
inline
static void *tcp_buf_ptr_plus(struct tcp_buf *buf,unsigned short value)
{
    unsigned short x=buf->end+value;

    return buf->data+x;
}

static void *tcp_buf_memcpy(struct tcp_buf *buf,void *data,unsigned short size)
{
    unsigned char *dest,*src=data;

    for(int n=0;n<size;n++){
        dest=tcp_buf_ptr_plus(buf,n);
        *dest=*src++;
    }
    return dest;
}

void tcp_buf_init(struct tcp_buf *buf)
{
    buf->begin=0;
    buf->end=0;
    buf->used_size=0;
}

int tcp_buf_copy_from_tcp_buf(struct tcp_buf *buf,void *res,unsigned short copy_max_size)
{
    unsigned short copy_size=buf->end-buf->begin;
    unsigned short t;
    unsigned char *ptr=res;
    copy_size=copy_max_size>copy_size?copy_size:copy_max_size;

    for(int n=0;n<copy_size;n++){
        t=buf->begin+n;
        *ptr++=*(buf->data+t);
    }

    return copy_size;
}

int tcp_buf_copy_to_tcp_buf(struct tcp_buf *buf,void *data,unsigned short data_size)
{
    unsigned short copy_size=0xffff-buf->used_size;

    if(data_size>copy_size){
        DBG("no buf for write\r\n");
        return -1;
    }

    tcp_buf_memcpy(buf,data,data_size);

    buf->end+=data_size;
    buf->used_size+=data_size;

    return data_size;
}

int tcp_buf_data_ptr_move(struct tcp_buf *buf,unsigned short move_size)
{

    if(buf->used_size<move_size) {
        DBG("wrong move_size argument\r\n");
        return -1;
    }

    buf->begin+=move_size;

    // 如果开始和结束位置一致说明数据已经被清空完毕,直接置0
    if(buf->begin==buf->end){
        buf->begin=0;
        buf->end=0;
    }

    buf->used_size-=move_size;
    return 0;
}

inline
unsigned short tcp_buf_free_buf_get(struct tcp_buf *buf)
{
    return 0xffff-buf->used_size;
}