//
// Created by KaiMei on 2019/9/8.
//

#include<stdio.h>
#include<sys/stat.h>
#include<unistd.h>

#include "pfile.h"

void pfile_write(const char *path,pid_t pid)
{
    FILE *f=fopen(path,"w");
    fwrite(&pid,sizeof(pid_t),1,f);
    fclose(f);
}

pid_t pfile_read(const char *path)
{
    pid_t pid;

    if(access(path,F_OK)<0) return -1;

    FILE *f=fopen(path,"r");

    fread(&pid,sizeof(pid_t),1,f);
    fclose(f);

    return pid;
}