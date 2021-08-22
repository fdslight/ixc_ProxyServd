#include<sys/select.h>
#include<errno.h>
#include<string.h>

#include "ev.h"
#include "ev_select.h"

#include "../debug.h"

/// 读集合
static fd_set ev_select_rset;
/// 写集合
static fd_set ev_select_wset;
static struct ev_select ev_select;

static int ev_select_add_read(struct ev *ev)
{	
	return 0;
}

static int ev_select_add_write(struct ev *ev)
{
	return 0;
}

static int ev_select_del_read(struct ev *ev)
{
	return 0;
}

static int ev_select_del_write(struct ev *ev)
{
	return 0;
}

static void ev_select_init_events(struct ev *ev)
{
	if(ev->is_added_read && !FD_ISSET(ev->fileno,&ev_select_rset)){
		FD_SET(ev->fileno,&ev_select_rset);
	}
	
	if(!ev->is_added_read && FD_ISSET(ev->fileno,&ev_select_rset)){
		FD_CLR(ev->fileno,&ev_select_rset);
	}
	
	if(ev->is_added_write && !FD_ISSET(ev->fileno,&ev_select_wset)){
		FD_SET(ev->fileno,&ev_select_wset);
	}
	
	if(!ev->is_added_write && FD_ISSET(ev->fileno,&ev_select_wset)){
		FD_CLR(ev->fileno,&ev_select_wset);
	}

	if(ev->fileno>ev_select.fd_max) ev_select.fd_max=ev->fileno;
}

static void ev_select_ev_handle(struct ev *ev)
{
	int is_readable=0,is_writable=0;
	
	if(FD_ISSET(ev->fileno,&ev_select_rset)) is_readable=1;
	if(FD_ISSET(ev->fileno,&ev_select_wset)) is_writable=1;
	
	if(is_readable && !ev->is_deleted && NULL!=ev->readable_fn){
		ev->readable_fn(ev);
	}
	
	if(is_writable && !ev->is_deleted && NULL!=ev->writable_fn){
		ev->writable_fn(ev);
	}
}

static int ev_select_ioloop(struct ev_set *ev_set)
{
	struct timeval timeval;
	int rs;
	
	// 这里需要重置文件最大描述符
	ev_select.fd_max=0;
	// 遍历映射重新生成rset与wset
	ev_each(ev_set,ev_select_init_events);

	timeval.tv_sec=ev_set->wait_timeout;
	timeval.tv_usec=0;

	rs=select(ev_select.fd_max+1,&ev_select_rset,&ev_select_wset,NULL,&timeval);
	
	if(rs<0){
		switch(errno){
			case EBADF:
				STDERR("wrong file descriptor\r\n");
				break;
			case EFAULT:
				STDERR("wrong arguments\r\n");
			case EINTR:
				break;
			default:
				STDERR("select event error\r\n");
				break;
		}
		return -1;
	}
	// 处理发生的事件
	ev_each(ev_set,ev_select_ev_handle);

	return 0;
}

static int ev_select_create(struct ev *ev)
{
	return 0;
}

static void ev_select_delete(struct ev *ev)
{

}

int ev_select_init(struct ev_set *ev_set)
{
	bzero(&ev_select,sizeof(struct ev_select));
	
	FD_ZERO(&ev_select_rset);
	FD_ZERO(&ev_select_wset);

	ev_select.ev_set=ev_set;

	ev_set->ev_create_fn=ev_select_create;
	ev_set->ev_delete_fn=ev_select_delete;
	ev_set->ioloop_fn=ev_select_ioloop;
	
	ev_set->add_read_ev_fn=ev_select_add_read;
	ev_set->add_write_ev_fn=ev_select_add_write;
	ev_set->del_read_ev_fn=ev_select_del_read;
	ev_set->del_write_ev_fn=ev_select_del_write;
	
	return 0;
}

void ev_select_uninit(struct ev_set *ev_set)
{
	
}

