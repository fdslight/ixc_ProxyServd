/** 循环执行相关代码 **/
#ifndef SYSLOOP_H
#define SYSLOOP_H

struct sysloop;

/// 系统循环回调函数
typedef void(*sysloop_fn_cb_t)(struct sysloop *);

struct sysloop{
    struct sysloop *prev;
    struct sysloop *next;

    sysloop_fn_cb_t fn_cb;
    void *data;
};

int sysloop_init(void);
void sysloop_uninit(void);

struct sysloop *sysloop_add(sysloop_fn_cb_t cb_fb,void *data);
void sysloop_del(struct sysloop *sysloop);

/// 执行循环,调用此函数时一定要注意不要调用sysroot_del函数,否则可能会造成内存非法访问
void sysloop_do(void);

#endif