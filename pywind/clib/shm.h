#ifndef SHM_H
#define SHM_H


/// 创建一块共享内存
int shm_shared_create(const char *path,size_t size,int flags);
/// 删除共享内存
void shm_shared_delete(const char *path);

/// 映射共享内存到当前地址空间
void *shm_shared_get_ref(const char *path);
/// 取消当前进程与共享内存的连接
void shm_shared_no_ref(void *shmaddr);

#endif