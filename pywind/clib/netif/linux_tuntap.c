#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include<sys/socket.h>
#include<string.h>
#include<sys/ioctl.h>
#include<netinet/in.h>
#include<unistd.h>

#include "tuntap.h"

#include "../debug.h"

static int __tuntap_create(char *name,int flags)
{
    struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0){
        STDERR("cannot open /dev/net/tun\r\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags |= flags;

	if (*name != '\0'){
		strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
		ifr.ifr_name[IFNAMSIZ-1]='\0';
	}else{
        STDERR("wrong tuntap_name\r\n");
        return -1;
    }

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0){
		close(fd);
        STDERR("cannot ioctl tuntap device\r\n");
		return -1;
	}

	strcpy(name, ifr.ifr_name);

	return fd;
}

static void __tuntap_close(int fd,const char *name)
{
	close(fd);
}

static int __tuntap_up(const char *name)
{
	int s;
	struct ifreq ifr;
	short flag;

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) return -1;
	
	strcpy(ifr.ifr_name, name);

	flag = IFF_UP;
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) return -1;
	ifr.ifr_ifru.ifru_flags |= flag;

	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) return -1;
	return 0;
}

int tundev_create(char *tundev_name)
{
	return __tuntap_create(tundev_name,IFF_TUN | IFF_NO_PI);
}

void tundev_close(int fd, const char *name)
{
    close(fd);
}

int tundev_up(const char *name)
{
	return __tuntap_up(name);
}

int tundev_set_nonblocking(int fd)
{
	int flags;

    flags=fcntl(fd,F_GETFL,0);
    return fcntl(fd,F_SETFL,flags | O_NONBLOCK);
}

int tapdev_create(char *tap_name)
{
	return __tuntap_create(tap_name,IFF_TAP | IFF_NO_PI);
}

void tapdev_close(int fd,const char *name)
{
	__tuntap_close(fd,name);
}

int tapdev_up(const char *name)
{
	return __tuntap_up(name);
}

int tapdev_set_nonblocking(int fd)
{
	int flags;

    flags=fcntl(fd,F_GETFL,0);
    return fcntl(fd,F_SETFL,flags | O_NONBLOCK);
}