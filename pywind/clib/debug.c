
#include<time.h>
#include<stdio.h>

#include "debug.h"

void __print_time(FILE *fp)
{
    char time_buf[512];
    struct tm *time_ptr;
    time_t raw_time;

    time(&raw_time);
    time_ptr=localtime(&raw_time);
    strftime(time_buf,512,"%Y-%m-%d %X %Z",time_ptr);fprintf(fp,"%s    ",time_buf);
}