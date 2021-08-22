#include<stdio.h>
#include<sys/epoll.h>

#include "../ev/ev.h"
#include "../ev/rpc.h"
#include "../debug.h"

static struct ev_set ixc_ev_set;

int main(int argc,char *arv[])
{
    int rs=ev_set_init(&ixc_ev_set,0);
    rs=rpc_create(&ixc_ev_set,"/tmp/rpc.sock",NULL);

    //DBG("%d %d\r\n",EPOLLIN,EPOLLOUT);

    rs=ev_loop(&ixc_ev_set);

    
    return 0;
}