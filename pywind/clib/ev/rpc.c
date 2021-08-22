
#include<arpa/inet.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<errno.h>
#include<sys/un.h>
#include<stddef.h>
#include<time.h>

#include "rpc.h"
#include "ev.h"
#include "../debug.h"

static struct rpc rpc;
static int rpc_is_initialized=0;

static int rpc_session_create(int fd,struct sockaddr *sockaddr,socklen_t sock_len);

static struct rpc_session *rpc_session_malloc(void)
{
	struct rpc_session *s=NULL;

	if(NULL==rpc.empty_head){
		s=malloc(sizeof(struct rpc_session));
		if(NULL==s){
			STDERR("cannot malloc struct rpc_session\r\n");
			return NULL;
		}
		bzero(s,sizeof(struct rpc_session));
		s->fd=-1;
		
		return s;
	}

	s=rpc.empty_head;
	rpc.empty_head=s->next;
	rpc.free_session_count-=1;

	bzero(s,sizeof(struct rpc_session));

	s->fd=-1;

	return s;
}

static void rpc_session_free(struct rpc_session *session)
{
	if(NULL==session) return;
	if(rpc.free_session_count>=rpc.free_session_max){
		free(session);
		return;
	}

	session->next=rpc.empty_head;

	rpc.empty_head=session;
	rpc.free_session_count+=1;
}

static struct rpc_fn_info *rpc_fn_info_get(const char *name)
{
	struct rpc_fn_info *result=NULL,*t=rpc.fn_head;
	while(NULL!=t){
		if(strcmp(name,t->func_name)){
			t=t->next;
			continue;
		}
		result=t;
		break;
	}

	return result;
}

static int rpc_accept(struct ev *ev)
{
	int rs;
	struct sockaddr_un un;
	socklen_t addrlen=sizeof(struct sockaddr_un);

	while(1){
		rs=accept(rpc.fileno,(struct sockaddr *)&un,&addrlen);
		//DBG_FLAGS;
		if(rs<0) break;
		//DBG_FLAGS;
		rpc_session_create(rs,(struct sockaddr *)&un,addrlen);
	}

	return 0;
}

static int rpc_fn_req(const char *name,void *arg,unsigned short arg_size,void *result,unsigned short *res_size)
{
	struct rpc_fn_info *info;
	char *s=result;

	*s='\0';

	info=rpc_fn_info_get(name);

	if(NULL==info){
		sprintf(s,"not found function %s",name);
		*res_size=strlen(s);
		
		return RPC_ERR_FN_NOT_FOUND;
	}

	return info->fn(arg,arg_size,result,res_size);
}

int rpc_create(struct ev_set *ev_set,const char *path,rpc_fn_req_t fn_req)
{
	int listenfd=-1,rs=0,size;
	struct sockaddr_un un;
	
	listenfd=socket(AF_UNIX,SOCK_STREAM,0);

	if(listenfd<0){
		STDERR("cannot create listen fileno\r\n");
		return -1;
	}

	bzero(&un,sizeof(struct sockaddr_un));

	un.sun_family=AF_UNIX;
	strcpy(un.sun_path,path);

	size=offsetof(struct sockaddr_un,sun_path)+strlen(un.sun_path);

	rs=bind(listenfd,(struct sockaddr *)&un,size);
	
	if(rs<0){
		STDERR("cannot bind address %s errno:%d\r\n",path,errno);
		close(listenfd);
		return -1;
	}
	
	rs=listen(listenfd,10);

	if(rs<0){
		STDERR("cannot listen address %s errno:%d\r\n",path,errno);
		close(listenfd);
		return -1;
	}

	rs=ev_setnonblocking(listenfd);
	if(rs<0){
		close(listenfd);
		STDERR("cannot set nonblocking\r\n");
		return -1;
	}

	bzero(&rpc,sizeof(struct rpc));

	rpc.fileno=listenfd;
	rpc.ev_set=ev_set;
	strcpy(rpc.path,path);

	if(NULL!=fn_req) rpc.fn_req=fn_req;
	else rpc.fn_req=rpc_fn_req;

	rpc.ev=ev_create(ev_set,rpc.fileno);
	if(NULL==rpc.ev){
		STDERR("cannot create ev for RPC\r\n");
		close(listenfd);
		return -1;
	}

	EV_INIT_SET(rpc.ev,rpc_accept,NULL,NULL,NULL,NULL);
	
	rs=ev_modify(ev_set,rpc.ev,EV_READABLE,EV_CTL_ADD);
	rpc_is_initialized=1;

	DBG("rpc create OK\r\n");

	return rs;
}

int rpc_fn_reg(const char *name,rpc_fn_call_t fn)
{
	struct rpc_fn_info *info=rpc_fn_info_get(name);
	if(NULL==info){
		STDERR("cannot reg rpc function %s,it is exists\r\n",name);
		return -1;
	}
	if(strlen(name)>0xff){
		STDERR("cannot reg rpc function %s,the function name is too long\r\n",name);
		return -2;
	}

	info=malloc(sizeof(struct rpc_fn_info));
	if(NULL==info){
		STDERR("cannot reg rpc function %s,no memory for malloc struct rpc_fn_info\r\n",name);
		return -3;
	}
	bzero(info,sizeof(struct rpc_fn_info));
	strcpy(info->func_name,name);
	info->fn=fn;
	info->next=rpc.fn_head;
	rpc.fn_head=info;
	
	return 0;
}

void rpc_fn_unreg(const char *name)
{
	struct rpc_fn_info *info=rpc_fn_info_get(name);
	struct rpc_fn_info *t=rpc.fn_head;
	if(NULL==info) return;
	if(rpc.fn_head==info){
		rpc.fn_head=info->next;
		free(info);
		return;
	}

	while(NULL!=t){
		if(t->next==info){
			t->next=info->next;
			free(info);
			break;
		}
		t=t->next;
	}
}


/// 解析RPC请求
static int rpc_session_parse_rpc_req(struct ev *ev,struct rpc_session *session)
{
	struct rpc_req *req=(struct rpc_req *)(session->recv_buf);
	unsigned short tot_len,res_size;
	char func_name[512];
	struct rpc_resp *resp=(struct rpc_resp *)(session->sent_buf);
	int err_code;

	// 缓冲区收到的数据必须等于大于2个字节
	if(session->recv_buf_end<2) return 0;

	tot_len=ntohs(req->tot_len);
	// 正常情况下tot len会比收到的数据大
	if(tot_len<session->recv_buf_end) return -1;
	// tot len的最小长度
	if(tot_len<264) return -1;
	if(tot_len>session->recv_buf_end) return 0;

	session->sent_buf_end=0;
	session->sent_buf_begin=0;

	bzero(func_name,512);
	memcpy(func_name,req->func_name,256);

	// 调用函数执行并返回结果
	err_code=rpc.fn_req(func_name,req->arg_data,tot_len-264,&(resp->message),&res_size);
	// 此处发送响应
	resp->is_error=htonl(err_code);
	resp->tot_len=htons(res_size+16);

	session->sent_buf_end=res_size+16;
	ev_modify(rpc.ev_set,ev,EV_WRITABLE,EV_CTL_ADD);
	ev->up_time=time(NULL);

	return 0;
}

static int rpc_session_readable_fn(struct ev *ev)
{
	ssize_t recv_size;
	int rs;
	struct rpc_session *session=ev->data;

	//DBG_FLAGS;

	for(int n=0;n<10;n++){
		recv_size=recv(ev->fileno,&session->recv_buf[session->recv_buf_end],0xffff-session->recv_buf_end,0);
		// 如果接收到数据为0说明对端已经关闭连接
		if(0==recv_size){
			ev_delete(rpc.ev_set,ev);
			break;
		}
		if(recv_size>0){
			session->recv_buf_end+=recv_size;
			rs=rpc_session_parse_rpc_req(ev,session);
			if(rs<0){
				DBG("wrong RPC request\r\n");
				ev_delete(rpc.ev_set,ev);
				break;
			}
			break;
		}
		if(EAGAIN==errno) break;

		DBG("recv rpc data wrong from fd %d errno %d\r\n",ev->fileno,errno);
		ev_delete(rpc.ev_set,ev);
		break;
		
	}

	return 0;
}

static int rpc_session_writable_fn(struct ev *ev)
{
	ssize_t sent_size;
	struct rpc_session *session=ev->data;

	while(1){
		sent_size=send(ev->fileno,session->sent_buf+session->sent_buf_begin,session->sent_buf_end-session->sent_buf_begin,0);
		if(sent_size>=0){
			session->sent_buf_begin+=sent_size;
			// 数据已经被发送完毕那么重置
			if(session->sent_buf_begin==session->sent_buf_end){
				session->sent_buf_begin=0;
				session->sent_buf_end=0;
				ev_modify(rpc.ev_set,ev,EV_WRITABLE,EV_CTL_DEL);
				break;
			}
			continue;
		}

		if(EAGAIN==errno) break;
		ev_delete(rpc.ev_set,ev);
	}

	return 0;
}

static int rpc_session_timeout_fn(struct ev *ev)
{
	time_t now=time(NULL);
	
	if(now-ev->up_time<10){
		ev_timeout_set(rpc.ev_set,ev,10);
		return 0;
	}

	ev_delete(rpc.ev_set,ev);

	return 0;
}

static int rpc_session_del_fn(struct ev *ev)
{
	struct rpc_session *session=ev->data;

	DBG("delete rpc session %d\r\n",session->fd);
	
	close(session->fd);
	rpc_session_free(session);

	return 0;
}

static int rpc_session_create(int fd,struct sockaddr *sockaddr,socklen_t sock_len)
{
	struct rpc_session *session=rpc_session_malloc();
	int rs;
	struct ev *ev;

	if(NULL==session){
		close(fd);
		STDERR("cannot create session for fd %d\r\n",fd);
		return -1;
	}

	if(ev_setnonblocking(fd)<0){
		close(fd);
		STDERR("cannot set nonblocking\r\n");
		rpc_session_free(session);
		return -1;
	}

	session->fd=fd;

	ev=ev_create(rpc.ev_set,fd);

	if(NULL==ev){
		rpc_session_free(session);
		close(fd);
		STDERR("cannot create event for fd %d\r\n",fd);
		return -1;
	}

	if(ev_timeout_set(rpc.ev_set,ev,10)<0){
		STDERR("cannot set timeout for fd %d\r\n",fd);
		ev_delete(rpc.ev_set,ev);
		return -1;
	}

	EV_INIT_SET(ev,rpc_session_readable_fn,rpc_session_writable_fn,rpc_session_timeout_fn,rpc_session_del_fn,session);
	rs=ev_modify(rpc.ev_set,ev,EV_READABLE,EV_CTL_ADD);

	if(rs<0){
		ev_delete(rpc.ev_set,ev);
		STDERR("cannot add to readablefor fd %d\r\n",fd);
		return -1;
	}

	DBG("create rpc session OK\r\n");

	return 0;
}

void rpc_delete(void)
{
	struct rpc_fn_info *info=rpc.fn_head,*t;

	if(!rpc_is_initialized) return;

	while(NULL!=info){
		t=info->next;
		free(info);
		info=t;
	}

	close(rpc.fileno);

	if(!access(rpc.path,F_OK)) remove(rpc.path);
	rpc_is_initialized=0;
}

int rpc_session_pre_alloc_set(int count)
{
	if(count<0) return -1;
	rpc.free_session_max=count;

	return 0;
}