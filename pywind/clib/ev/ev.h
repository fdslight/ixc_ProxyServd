#ifndef EV_H
#define EV_H

#include "../map.h"
#include "../timer.h"

#define EV_NO 0
#define EV_READABLE 1
#define EV_WRITABLE 2

/// 加入事件
#define EV_CTL_ADD 1
/// 删除事件
#define EV_CTL_DEL 2

/// 最大超时时间
#ifndef EV_TIMEOUT_MAX
#define EV_TIMEOUT_MAX 30
#endif

/// Kqueue的最大该表长度
#ifndef EV_EV_MAX
#define EV_EV_MAX 1024
#endif

struct ev;
struct ev_set;

/// 事件函数回调
// 返回0表示继续执行,非0表示发生错误
typedef int (*ev_fn_cb_t)(struct ev *);

/// 处理事件函数
typedef int (*ev_ioloop_fn_cb_t)(struct ev_set *);
/// 修改事件处理函数
typedef int (*ev_modify_fn_t)(struct ev *);

/// 事件创建函数
typedef int (*ev_create_fn_t)(struct ev *);
/// 事件删除回调函数
typedef void (*ev_delete_fn_t)(struct ev *);
/// 事件遍历回调函数
typedef void (*ev_each_fn_t)(struct ev *);

/// 定义自己的循环
typedef void (*ev_myloop_fn_t)(void);

struct ev{
	struct ev *prev;
	struct ev *next;
	
	struct time_data *tdata;
	void *data;

	ev_fn_cb_t readable_fn;
	ev_fn_cb_t writable_fn;
	ev_fn_cb_t timeout_fn;
	ev_fn_cb_t del_fn;
	
	time_t up_time;
	
	/// 是否已经加入读或者写事件
	int is_added_read;
	int is_added_write;
	
	int fileno;
	// 是否已经删除资源
	int is_deleted;
};

#define EV_INIT_SET(ev,_readable_fn,_writable_fn,_timeout_fn,_del_fn,_data) \
(ev)->data=_data;\
(ev)->readable_fn=_readable_fn;\
(ev)->writable_fn=_writable_fn;\
(ev)->timeout_fn=_timeout_fn;\
(ev)->del_fn=_del_fn

/// 事件集合
struct ev_set{
	struct map *m;
	struct time_wheel *time_wheel;
	// 需要删除的头部
	struct ev *del_head;
	// 事件集合
	struct ev *ev_head;
	// 空的事件列表
	struct ev *empty_ev_head;
	
	ev_create_fn_t ev_create_fn;
	ev_delete_fn_t ev_delete_fn;
	ev_ioloop_fn_cb_t ioloop_fn;
	// 加入事件回调
	ev_modify_fn_t add_read_ev_fn;
	ev_modify_fn_t add_write_ev_fn;
	// 删除事件回调
	ev_modify_fn_t del_read_ev_fn;
	ev_modify_fn_t del_write_ev_fn;

	ev_myloop_fn_t myloop_fn;
	
	void *data;

	time_t wait_timeout;
	int is_select;
	// 最大空的EV数目
	int empty_ev_max;
	// 当前空的EV数目
	int cur_empty_ev_count;
};

/// IO超时等待时间
#define EV_SET_TIMEOUT_WAIT(_ev_set) (_ev_set)->wait_timeout
/// 私有数据
#define EV_SET_PRIV_DATA (_ev_set) (_ev_set)->data

/// 事件集合初始化
// force_select 如果非0表示强制使用select事件模型,否则根据操作系统选择
int ev_set_init(struct ev_set *ev_set,int force_select);
void ev_set_uninit(struct ev_set *ev_set);

/// 创建EV
struct ev *ev_create(struct ev_set *ev_set,int fileno);
/// 删除事件
void ev_delete(struct ev_set *ev_set,struct ev *ev);
/// 修改事件
int ev_modify(struct ev_set *ev_set,struct ev *ev,int ev_no,int ev_ctl);
/// 事件循环
int ev_loop(struct ev_set *ev_set);
/// 设置超时事件超时时间
int ev_timeout_set(struct ev_set *ev_set,struct ev *ev,time_t timeout);
/// 获取事件对象
struct ev *ev_get(struct ev_set *ev_set,int fileno);
/// 设置为非阻塞模式
int ev_setnonblocking(int fd);
/// 遍历事件
void ev_each(struct ev_set *ev_set,ev_each_fn_t fn);

#endif
