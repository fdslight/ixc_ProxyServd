
#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/shm.h>
#include<unistd.h>
#include<errno.h>
#include<string.h>

#include "shm.h"
#include "debug.h"

static int shm_key_get_from_file(const char *path)
{
    FILE *f;
    int id;
    // 首先检查文件是否存在
    if(access(path,F_OK)){
        STDERR("the shared memory file %s not exists at function %s\r\n",path,__func__);
        return -1;
    }
    f=fopen(path,"r");
    fread(&id,sizeof(id),1,f);
    fclose(f);
    
    return id;
}

static int shm_get(key_t key, size_t size, int shmflg)
{
    int rs=shmget(key,size,shmflg);
    if(rs<0){
        switch (errno){
        case EINVAL:
            STDERR("shmmin or shmmax error at function %s\r\n",__func__);
            break;
        case EEXIST:
            STDERR("shared memory exists at function %s\r\n",__func__);
            break;
        case EIDRM:
            STDERR("shared memory has been deleted at function %s\r\n",__func__);
            break;
        case ENOSPC:
            STDERR("shared memory shmall at function %s\r\n",__func__);
            break;
        case ENOENT:
            STDERR("not exists from key at function %s\r\n",__func__);
            break;
        case EACCES:
            STDERR("cannot access shared memory %s\r\n",__func__);
            break;
        case ENOMEM:
            STDERR("the os no memory at function %s\r\n",__func__);
            break;
        }

        return rs;
    }

    return rs;
}

int shm_shared_create(const char *path,size_t size,int flags)
{
    int id=shm_get(IPC_PRIVATE,size,flags);
    FILE *f=NULL;

    if(id>=0){
        f=fopen(path,"w");
        fwrite(&id,sizeof(int),1,f);
        fclose(f);
    }

    return id;
}

void shm_shared_delete(const char *path)
{
    int id=shm_key_get_from_file(path);

    if(id<0) return;

    shmctl(id,IPC_RMID,NULL);
    // 移除文件
    remove(path);
}

void *shm_shared_get_ref(const char *path)
{
    void *result;
    int id=shm_key_get_from_file(path);

    if(id<0) return NULL;

    result=shmat(id,NULL, SHM_RND);
    
    if((long long)(result)<0){
        switch(errno){
            case EACCES:
                STDERR("not permit access shared memory at function %s\r\n",__func__);
                break;
            case EINVAL:
                STDERR("invalid shmid or shmaddr at function %s\r\n",__func__);
                break;
            case ENOMEM:
                STDERR("no system memory at function %s\r\n",__func__);
                break;
        }

        return NULL;
    }

    return result;
}

void shm_shared_no_ref(void *shmaddr)
{
    shmdt(shmaddr);
}