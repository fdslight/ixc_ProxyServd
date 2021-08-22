/** 基于TCP套接字的RPC **/
#ifndef RPC_H
#define RPC_H

#include<sys/types.h>
#include<sys/socket.h>

#include "ev.h"

/// RPC最大数据大小,请不要修改这个值
#define RPC_DATA_MAX 0x10000
/// RPC请求数据结构体
struct rpc_req{
	// 总体数据长度,包括函数名和命名空间
	unsigned short tot_len;
	char pad[6];
	// 函数名
	char func_name[256];
	unsigned char arg_data[RPC_DATA_MAX];
};

/// RPC故障码定义
enum{
	RPC_ERR_NO=0,
	// 未找到函数名
	RPC_ERR_FN_NOT_FOUND,
	// 函数参数错误
	RPC_ERR_ARG,
	// 其他错误
	RPC_ERR_OTHER
};

/// RPC响应数据结构体,如果故障那么响应故障文本信息
struct rpc_resp{
	// 总体数据长度
	unsigned short tot_len;
	char pad[10];
	int is_error;
	unsigned char message[RPC_DATA_MAX];
};

/// RPC函数调用回调函数
typedef int (*rpc_fn_call_t)(void *,unsigned short,void *,unsigned short *);

/// 函数调佣类型
typedef int (*rpc_fn_req_t)(const char *,void *,unsigned short,void *,unsigned short *);

struct rpc_session{
	struct rpc_session *next;
	/// 接收缓冲区
	unsigned char recv_buf[0x10000];
	unsigned char sent_buf[0x10000];
	char address[256];
	/// 是否处理完毕
	int handle_ok;
	/// 接收缓冲区结束位置
	int recv_buf_end;
	// 发送缓冲区开始位置
	int sent_buf_begin;
	int sent_buf_end;
	int fd;
	unsigned short port;
};

/// RPC函数信息
struct rpc_fn_info{
	struct rpc_fn_info *next;
	rpc_fn_call_t fn;
	char func_name[0xff];
};

struct rpc{
	struct rpc_session *empty_head;
	struct rpc_fn_info *fn_head;
	struct ev *ev;
	struct ev_set *ev_set;
	// 如果设置了请求,那么系统将不会自动查找函数,需要用户自己编写自动查找函数
	rpc_fn_req_t fn_req;
	char path[1024];
	// 最大空闲session大小
	int free_session_max;
	// 空闲session计数
	int free_session_count;
	int fileno;	
};

/// 创建RPC对象
int rpc_create(struct ev_set *ev_set,const char *path,rpc_fn_req_t fn_req);
/// 注册函数
int rpc_fn_reg(const char *name,rpc_fn_call_t fn);
/// 取消函数注册
void rpc_fn_unreg(const char *name);
/// 删除RPC对象
void rpc_delete(void);

/// 会话内存预先分配设置
int rpc_session_pre_alloc_set(int count);

#endif
