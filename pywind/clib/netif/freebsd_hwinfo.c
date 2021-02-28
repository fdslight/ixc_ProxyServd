#include <stdio.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/un.h>

#include "hwinfo.h"

struct hwinfo *hwinfo_get_all(size_t *nc_num)
{
    int rs = -1;
    char is_same;
    unsigned char hwaddr[6];
    struct ifaddrs *ifaddr, *tmpaddr = NULL;
    struct hwinfo *hwinfo_head = NULL, *tmp_hwinfo, *old_hwinfo;

    *nc_num = 0;

    rs = getifaddrs(&ifaddr);

    if (rs)
    {
        fprintf(stderr, "get nic address failed\r\n");
        return NULL;
    }

    tmpaddr = ifaddr;

    while (NULL != tmpaddr)
    {

        if (IFF_LOOPBACK & tmpaddr->ifa_flags)
        {
            tmpaddr = tmpaddr->ifa_next;
            continue;
        }

        /**if (IFF_UP != (IFF_UP & tmpaddr->ifa_flags))
        {
            tmpaddr = tmpaddr->ifa_next;
            continue;
        }**/

        /**if (AF_INET != tmpaddr->ifa_addr->sa_family && AF_INET6 != tmpaddr->ifa_addr->sa_family)
        {
            tmpaddr = tmpaddr->ifa_next;
            continue;
        }**/

        rs = hwinfo_get(tmpaddr->ifa_name, hwaddr);

        if (rs < 0)
        {
            tmpaddr = tmpaddr->ifa_next;
            continue;
        }

        // 检查是否重复
        is_same = 0;

        tmp_hwinfo = hwinfo_head;

        while (NULL != tmp_hwinfo)
        {
            if (!strcmp(tmp_hwinfo->name, tmpaddr->ifa_name))
            {
                is_same = 1;
                break;
            }
            tmp_hwinfo = tmp_hwinfo->next;
        }

        if (is_same)
        {
            tmpaddr = tmpaddr->ifa_next;
            continue;
        }

        tmp_hwinfo = malloc(sizeof(struct hwinfo));
        tmp_hwinfo->next = NULL;

        if (NULL == tmp_hwinfo)
        {
            hwinfo_free(hwinfo_head);
            hwinfo_head = NULL;
            fprintf(stderr, "no memory for malloc hwinfo at funciton %s\r\n", __func__);
            break;
        }

        strcpy(tmp_hwinfo->name, tmpaddr->ifa_name);
        memcpy(tmp_hwinfo->hwaddr,hwaddr,6);

        tmpaddr = tmpaddr->ifa_next;

        if (NULL == hwinfo_head)
        {
            hwinfo_head = tmp_hwinfo;
        }
        else
        {
            old_hwinfo->next = tmp_hwinfo;
        }

        *nc_num += 1;
        old_hwinfo = tmp_hwinfo;
    }

    freeifaddrs(ifaddr);

    return hwinfo_head;
}

void hwinfo_free(struct hwinfo *first)
{
    struct hwinfo *t, *hwinfo = first;

    while (NULL != hwinfo)
    {
        t = hwinfo->next;
        free(hwinfo);
        hwinfo = t;
    }
}


int hwinfo_get(const char *name, unsigned char *res)
{
    int mib[6];
    unsigned long length;
    char *buf, empty[6];
    struct if_msghdr *msghdr;
    struct sockaddr_dl *soaddr_dl;
    unsigned char *ptr;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;

    mib[5] = if_nametoindex(name);

    if (0 == mib[5])
    {
        fprintf(stderr, "module if_nametoindex error\r\n");
        return -1;
    }

    if (sysctl(mib, 6, NULL, &length, NULL, 0) < 0)
    {
        fprintf(stderr, "sysctl 1 error");
        return -1;
    }

    buf = malloc(length);
    if (NULL == buf)
    {
        fprintf(stderr, "no memory at function %s\r\n", __func__);
        return -1;
    }

    if (sysctl(mib, 6, buf, &length, NULL, 0) < 0)
    {
        free(buf);
        return -1;
    }

    msghdr = (struct if_msghdr *)buf;
    soaddr_dl = (struct sockaddr_dl *)(msghdr + 1);

    ptr = (unsigned char *)LLADDR(soaddr_dl);

    bzero(empty, 6);

    if (!memcmp(ptr, empty, 6))
    {
        free(buf);
        return -1;
    }

    memcpy(res, ptr, 6);
    free(buf);

    return 0;
}
