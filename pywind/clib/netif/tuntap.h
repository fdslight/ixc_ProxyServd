#ifndef TUNTAP_H
#define TUNTAP_H

int tundev_create(char *tundev_name);
void tundev_close(int fd, const char *name);

///启用接口
int tundev_up(const char *name);

int tundev_set_nonblocking(int fd);

int tapdev_create(char *tap_name);
void tapdev_close(int fd,const char *name);
int tapdev_up(const char *name);
int tapdev_set_nonblocking(int fd);

#endif