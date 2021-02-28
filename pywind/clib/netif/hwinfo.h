#ifndef HWINFO_H
#define HWINFO_H

#include<sys/types.h>

struct hwinfo{
    struct hwinfo *next;
    unsigned char hwaddr[6];
    char name[256];
};

struct hwinfo *hwinfo_get_all(size_t *nc_num);
/// 当调用hwinfo_get_all时需要调用hwinfo_free释放内存
void hwinfo_free(struct hwinfo *first);
int hwinfo_get(const char *name, unsigned char *res);

/// 把网络序硬件地址转换成字符串
#define HWADDR_NET2STR(hwaddr,res) sprintf(res,"%02x:%02x:%02x:%02x:%02x:%02x",hwaddr[0],hwaddr[1],hwaddr[2],hwaddr[3],hwaddr[4],hwaddr[5])

#endif