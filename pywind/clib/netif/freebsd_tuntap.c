#include<sys/types.h>
#include<string.h>
#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>
#include<arpa/inet.h>
#include<sys/stat.h>
#include<net/if.h>
#include<sys/sysctl.h>
#include<net/if_tun.h>
#include<net/if_tap.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<sys/stat.h>
#include<sys/ioctl.h>

#include "tuntap.h"
#include "../debug.h"

static int __tuntap_create(char *tuntap_name,int is_tap)
{
    int newv = 1, fd, v;
    char oldv[64];
    size_t size;
    struct stat stat;

    char *name, buf[256];
    char sysctl_name[512];

    if(is_tap) strcpy(sysctl_name,"net.link.tap.devfs_cloning");
    else strcpy(sysctl_name,"net.link.tun.devfs_cloning");
    

    int rs = sysctlbyname(sysctl_name, oldv, &size, &newv, sizeof(int));

    if (rs < 0) return -1;

    if(is_tap) fd=open("/dev/tap",O_RDWR);
    else fd = open("/dev/tun", O_RDWR);

    fstat(fd, &stat);
    name = devname(stat.st_rdev, S_IFCHR);
    strcpy(tuntap_name, name);
    close(fd);

    strcpy(buf, "/dev/");
    strcat(buf, name);

    fd = open(buf, O_RDWR);
    v = 0;

    if(!is_tap) rs = ioctl(fd, TUNSLMODE, &v);
    else rs=0;
    
    if (rs < 0){
        tapdev_close(fd,name);
        STDERR("cannot set tuntap\r\n");
        return -1;
    }

    return fd;
}

static void __tuntap_close(int fd,const char *name)
{
    struct ifreq ifr;

    close(fd);
    bzero(&ifr, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, name);

    int sock = socket(PF_INET, SOCK_STREAM, 0);

    ioctl(sock, SIOCIFDESTROY, &ifr);
    close(sock);
}

int tundev_create(char *tundev_name)
{
    return __tuntap_create(tundev_name,0);
}

void tundev_close(int fd, const char *name)
{
    __tuntap_close(fd,name);
}

int tundev_up(const char *name){
    return 0;
}

int tapdev_create(char *tap_name)
{
    return __tuntap_create(tap_name,1);
}

void tapdev_close(int fd,const char *name)
{
    __tuntap_close(fd,name);
}

int tapdev_up(const char *name)
{
    return 0;
}