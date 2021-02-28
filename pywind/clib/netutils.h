#include<sys/types.h>

#ifndef __NETUTILS_H
#define __NETUTILS_H

struct netutil_iphdr{
    unsigned char ver_and_ihl;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_info;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char src_addr[4];
    unsigned char dst_addr[4];
};

struct netutil_ip6hdr{
    unsigned char ver_and_tc;
    unsigned char flow_label[3];
    unsigned short payload_len;
    unsigned char next_header;
    unsigned char hop_limit;
    unsigned char src_addr[16];
    unsigned char dst_addr[16];
};

struct netutil_udphdr{
    unsigned short src_port;
    unsigned short dst_port;
    union 
    {
        unsigned short length;
        unsigned short csum_coverage;
    };
    unsigned short checksum;
};

struct netutil_tcphdr{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned short header_len_and_flag;
    unsigned short win_size;
    unsigned short csum;
    unsigned short urgent_pointer;
};

#pragma pack(push)
#pragma pack(4)
struct netutil_icmphdr{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
};

struct netutil_icmpecho{
    struct netutil_icmphdr icmphdr;
    unsigned short id;
    unsigned short seq_num;
};

#pragma pack(pop)

/// 计算掩码
int msk_calc(unsigned char prefix,int is_ipv6,unsigned char *res);
/// 计算子网
int subnet_calc_with_prefix(unsigned char *address,unsigned char prefix,int is_ipv6,unsigned char *res);
int subnet_calc_with_msk(unsigned char *address,unsigned char *msk,int is_ipv6,unsigned char *res);

/** calc inrement csum **/
unsigned short csum_calc_incre(unsigned short old_field,unsigned short new_field,unsigned short old_csum);
unsigned short csum_calc(char *buffer,size_t size);

/// 计算广播地址
int net_broadcast_calc(unsigned char *address,unsigned char prefix,int is_ipv6,unsigned char *res);

/// 构建IPv4数据包头部
// 如果opt_len长度为0表示选项结束
int build_ipv4_header(struct netutil_iphdr *iphdr,const char options[][40],unsigned char every_opt_len[],void *res);

/// 构建UDP数据包
// return:返回数据包的大小
char *build_udp_packet(\
unsigned char *src_addr,unsigned char *dst_addr,unsigned short src_port,unsigned short dst_port,\
char *user_data,unsigned short user_data_len,char *res,int *offset,int is_ipv6,\
int is_udplite,int udplite_csum_coverage);

/// 检查是否是IPv4地址
int is_ipv4_address(const char *address);
/// 检查是否是IPv6地址
int is_ipv6_address(const char *address);
/// 是否是合法端口 
int is_valid_port(const char *s);

/// 检查IP头部是否合法
int check_ippkt_is_ok(struct netutil_iphdr *iphdr);

/// 重写IP地址,is_src不为0表示重写源地址,否则重写目标地址
void rewrite_ip_addr(struct netutil_iphdr *iphdr,unsigned char *new_addr,int is_src);

#endif