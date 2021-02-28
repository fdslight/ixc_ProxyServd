#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

#include "hwinfo.h"
#include "../debug.h"

struct hwinfo *hwinfo_get_all(size_t *nc_num)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[4096];
    struct ifreq *it,*end;
    struct hwinfo *rs_head=NULL,*tmp_info;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0){
        STDERR("cannot create socket\r\n");
        return NULL;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;

    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0){
        close(sock);
        STDERR("call ioctl failed\r\n");
        return NULL;
    }

    it = ifc.ifc_req;
    end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it){
        strcpy(ifr.ifr_name, it->ifr_name);

        if(ioctl(sock,SIOCGIFFLAGS,&ifr)){
            hwinfo_free(rs_head);
            rs_head=NULL;
            break;
        }

        // 不统计loopback
        if((ifr.ifr_flags & IFF_LOOPBACK)) continue;
        if(ioctl(sock,SIOCGIFHWADDR,&ifr)) continue;

        tmp_info=malloc(sizeof(struct hwinfo));

        if(NULL==tmp_info){
            hwinfo_free(rs_head);
            rs_head=NULL;
            STDERR("cannot malloc memory\r\n");
            break;
        }

        memcpy(tmp_info->hwaddr,&ifr.ifr_ifru.ifru_hwaddr.sa_data[0],6);
        strcpy(tmp_info->name,ifr.ifr_name);

        tmp_info->next=rs_head;
        rs_head=tmp_info;

    }

    return rs_head;
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
    size_t num;
    struct hwinfo *first=hwinfo_get_all(&num),*info;
    int rs=-1;

    info=first;

    while(NULL!=info){
        if(strcmp(info->name,name)){
            info=info->next;
            continue;
        }
        rs=0;
        memcpy(res,info->hwaddr,6);
        break;
    }

    hwinfo_free(first);
    
    return rs;
}