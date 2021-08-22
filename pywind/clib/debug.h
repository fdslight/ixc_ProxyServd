#ifndef DEBUG_H
#define DEBUG_H

#include<sys/types.h>
#include<stdio.h>
#include<stdlib.h>


void __print_time(FILE *fp);

#define STDERR(...) __print_time(stderr);fprintf(stderr,"%s:%s line_no:%d   ",__FILE__,__func__,__LINE__);fprintf(stderr,__VA_ARGS__)
#define STDOUT(...) __print_time(stdout);printf("%s:%s line_no:%d   ",__FILE__,__func__,__LINE__);printf(__VA_ARGS__)

#ifdef DEBUG
#include<sys/time.h>
#include<sys/types.h>

#define DBG(...)  STDOUT(__VA_ARGS__);fflush(stdout)
#define DBG_FLAGS STDOUT("\r\n");fflush(stdout)

#define ex_free(p) DBG(" ");free(p)
#define ex_malloc(size) DBG(" ");malloc(size)

#else

#define DBG(...)
#define DBG_FLAGS
#define ex_free(p) free(p)
#define ex_malloc(size) malloc(size)

#endif

#endif //DEBUG_H
