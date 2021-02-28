#ifndef DEBUG_H
#define DEBUG_H

#include<sys/types.h>
#include<stdio.h>
#include<time.h>
#include<stdlib.h>

char __time_buf[512];
struct tm *__time;
time_t __raw_time;

#define __TIME(fd)  time(&__raw_time);\
__time=localtime(&__raw_time);\
strftime(__time_buf,512,"%Y-%m-%d %X %A %Z",__time);fprintf(fd,"%s    ",__time_buf)

#define STDERR(...) __TIME(stderr);fprintf(stderr,"%s:%s %d   ",__FILE__,__func__,__LINE__);fprintf(stderr,__VA_ARGS__)
#define STDOUT(...) __TIME(stdout);printf("%s:%s %d   ",__FILE__,__func__,__LINE__);printf(__VA_ARGS__)

#ifdef DEBUG
#include<sys/time.h>
#include<sys/types.h>


#define DBG(...)  STDOUT(__VA_ARGS__)
#define DBG_FLAGS STDOUT("\r\n")

#define ex_free(p) DBG(" ");free(p)
#define ex_malloc(size) DBG(" ");malloc(size)

#else
#define DBG(...)
#define DBG_FLAGS
#define ex_free(p) free(p)
#define ex_malloc(size) malloc(size)
#endif

#endif //NETBUS_DEBUG_H
