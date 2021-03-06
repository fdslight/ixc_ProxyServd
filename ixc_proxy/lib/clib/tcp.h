#ifndef IP2SOCKS_TCP_H
#define IP2SOCKS_TCP_H

#include "mbuf.h"
#include "tcp_timer.h"
#include "tcp_buf.h"

#include "../../../pywind/clib/map.h"
#include "../../../pywind/clib/netutils.h"

#define TCP_ACK 0x0010
#define TCP_RST 0x0004
#define TCP_SYN 0x0002
#define TCP_FIN 0x0001

//////超时,单位是秒,注意这里的时间要小于TCP_TIMEOUT_MAX值
#define TCP_TIMEOUT_MAX 180
/// TCP SYN超时时间
#define TCP_TIMEOUT_SYN 8
/// TCP KEEP ALIVE超时时间
#define TCP_TIMEOUT_KEEP_ALIVE 120
/// TCP FIN超时时间
#define TCP_TIMEOUT_FIN 8


/// TCP状态
enum{
    // SYN已经发送
    TCP_ST_SYN_SND=1,
    TCP_ST_OK,
    // 发送FIN发送等待
    TCP_ST_FIN_SND_WAIT
};

/// 获取TCP标志
#define TCP_FLAGS(v,flags) (v & flags)

#define TCP_SENT_BUF(session) (&((session)->sent_buf))

/// TCP会话信息
struct tcp_session{
    // 数据时间对象
    struct tcp_timer_node *data_tm_node;
    // 连接时间对象
    struct tcp_timer_node *conn_tm_node;
    struct tcp_buf sent_buf;
    // TCP数据传输时间更新
    struct timeval data_time_up;
    // TCP连接时间更新
    struct timeval conn_time_up;
    // TCP的延迟时间
    time_t delay_ms;
    // 是否是IPv6地址
    int is_ipv6;
    // 会话ID
    unsigned char id[36];
    // 源地址
    unsigned char src_addr[16];
    // 目标地址
    unsigned char dst_addr[16];
    // 对端发送是否关闭
    int peer_sent_closed;
    // 本端发送是否关闭
    int my_sent_closed;
    // 定时器
    // tcp会话状态
    int tcp_st;
    // 对端TCP mss
    unsigned short peer_mss;
    // 本端TCP mss
    unsigned short my_mss;
    // 源端口号
    unsigned short sport;
    // 目的端口号
    unsigned short dport;
    // 序列号
    unsigned int seq;
    // 发送序列号计数器,把序列号加上此数值就是对端要确认的最大序列号
    unsigned int sent_seq_cnt;
    // 已经收到的对端最小可用连续序列号
    unsigned int peer_seq;
    // 窗口大小
#define TCP_DEFAULT_WIN_SIZE 0xffff
    unsigned short my_window_size;
    // 对端窗口大小
    unsigned short peer_window_size;
};

struct tcp_sessions{
    // IPv4 TCP会话
    struct map *sessions;
    // IPv6 TCP会话
    struct map *sessions6;
    unsigned long long conn_count;
    unsigned short ip_mss;
    unsigned short ip6_mss;
};

int tcp_init(void);
void tcp_uninit(void);
/// tcp mss设置
int tcp_mss_set(unsigned short mss,int is_ipv6);

void tcp_handle(struct mbuf *m,int is_ipv6);
/// 发送TCP数据包
int tcp_send(unsigned char *session_id,void *data,int length,int is_ipv6);
/// 关闭TCP连接
int tcp_close(unsigned char *session_id,int is_ipv6);
/// 窗口大小设置
int tcp_window_set(unsigned char *session_id,int is_ipv6,unsigned short win_size);

/// 获取TCP连接数
unsigned long long tcp_conn_count_get(void);

#endif