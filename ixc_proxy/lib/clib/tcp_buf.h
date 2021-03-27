#ifndef TCP_BUF_H
#define TCP_BUF_H

struct tcp_buf{
    unsigned char data[0x10007];
    unsigned short begin;
    unsigned short end;
    // 已经使用的缓冲区大小
    unsigned short used_size;
    char __pad[2];
};

/// 初始化TCP buf
void tcp_buf_init(struct tcp_buf *buf);

/// 从TCP缓冲区拷贝数据
// 如果发生错误,那么返回值小于0,否则返回拷贝的数据长度
int tcp_buf_copy_from_tcp_buf(struct tcp_buf *buf,void *res,unsigned short copy_max_size);
/// 拷贝数据到TCP缓冲区
// // 如果发生错误,那么返回值小于0,否则返回拷贝的数据长度
int tcp_buf_copy_to_tcp_buf(struct tcp_buf *buf,void *data,unsigned short data_size);
/// 移动缓冲区数据指针
// 函数发生错误返回非零值,未发生错误返回值为0
int tcp_buf_data_ptr_move(struct tcp_buf *buf,unsigned short move_size);
/// 获取空闲空间
unsigned short tcp_buf_free_buf_get(struct tcp_buf *buf);

#endif