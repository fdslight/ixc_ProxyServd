#define  PY_SSIZE_T_CLEAN
#define  PY_SSIZE_T_CLEAN

#include<Python.h>
#include<structmember.h>
#include<execinfo.h>
#include<signal.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include "mbuf.h"
#include "debug.h"
#include "ip.h"
#include "ipv6.h"
#include "proxy.h"
#include "udp.h"
#include "ipunfrag.h"
#include "ip6unfrag.h"
#include "static_nat.h"
#include "ipalloc.h"
#include "qos.h"

#include "../../../pywind/clib/sysloop.h"
#include "../../../pywind/clib/netif/tuntap.h"
#include "../../../pywind/clib/netutils.h"

typedef struct{
    PyObject_HEAD
}proxy_object;

/// 发送IP数据包回调函数
static PyObject *ip_sent_cb=NULL;
/// UDP接收回调函数
static PyObject *udp_recv_cb=NULL;

static void ixc_segfault_handle(int signum)
{
    void *bufs[4096];
    char **strs;
    int nptrs;

    nptrs=backtrace(bufs,4096);
    strs=backtrace_symbols(bufs,nptrs);
    if(NULL==strs) return;

    for(int n=0;n<nptrs;n++){
        fprintf(stderr,"%s\r\n",strs[n]);
    }
    free(strs);
    exit(EXIT_FAILURE);
}

int netpkt_send(struct mbuf *m)
{
    PyObject *arglist,*result;

    if(NULL==ip_sent_cb){
        STDERR("not set ip_sent_cb\r\n");
        return -1;
    }

    arglist=Py_BuildValue("(y#y#i)",m->data+m->begin,m->end-m->begin,m->id,16,m->from);
    result=PyObject_CallObject(ip_sent_cb,arglist);
 
    Py_XDECREF(arglist);
    Py_XDECREF(result);

    mbuf_put(m);

    return 0;
}

int netpkt_udp_recv(unsigned char *id,unsigned char *saddr,unsigned char *daddr,unsigned short sport,unsigned short dport,int is_udplite,int is_ipv6,void *data,int size)
{
    PyObject *arglist,*result;
    char src_addr[512],dst_addr[512];
    int fa;

    if(NULL==udp_recv_cb){
        STDERR("not set udp_recv_cb\r\n");
        return -1;
    }

    fa=is_ipv6?AF_INET6:AF_INET;

    bzero(src_addr,512);
    bzero(dst_addr,512);

    inet_ntop(fa,saddr,src_addr,512);
    inet_ntop(fa,daddr,dst_addr,512);

    arglist=Py_BuildValue("(y#ssHHNNy#)",id,16,src_addr,dst_addr,sport,dport,PyBool_FromLong(is_udplite),PyBool_FromLong(is_ipv6),data,size);
    result=PyObject_CallObject(udp_recv_cb,arglist);
 
    Py_XDECREF(arglist);
    Py_XDECREF(result);

    return 0; 
}

static void
proxy_dealloc(proxy_object *self)
{
    qos_uninit();
    ip6unfrag_uninit();
    ipunfrag_init();
    static_nat_uninit();
    ipalloc_uninit();

    sysloop_uninit();
    mbuf_uninit();
}

static PyObject *
proxy_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    proxy_object *self;
    int rs=0;
    self=(proxy_object *)type->tp_alloc(type,0);
    if(NULL==self) return NULL;

    rs=mbuf_init(64);
    if(rs<0){
        STDERR("cannot init mbuf\r\n");
        return NULL;
    }

    rs=sysloop_init();
    if(rs<0){
        STDERR("cannot init sysloop\r\n");
        return NULL;
    }

    rs=qos_init();
    if(rs<0){
        STDERR("cannot init qos\r\n");
        return NULL;
    }

    rs=ipalloc_init();
    if(rs<0){
        STDERR("cannot init ipalloc\r\n");
        return NULL;
    }

    rs=static_nat_init();
    if(rs<0){
        STDERR("cannot init static nat\r\n");
        return NULL;
    }

    rs=ipunfrag_init();
    if(rs<0){
        STDERR("cannot init ipunfrag\r\n");
        return NULL;
    }

    rs=ip6unfrag_init();
    if(rs<0){
        STDERR("cannot init ip6unfrag\r\n");
        return NULL;
    }

    signal(SIGSEGV,ixc_segfault_handle);

    return (PyObject *)self;
}

static int
proxy_init(proxy_object *self,PyObject *args,PyObject *kwds)
{
    PyObject *fn_ip_sent_cb;
    PyObject *fn_udp_recv_cb;

    if(!PyArg_ParseTuple(args,"OO",&fn_ip_sent_cb,&fn_udp_recv_cb)) return -1;
    if(!PyCallable_Check(fn_ip_sent_cb)){
        PyErr_SetString(PyExc_TypeError,"ip sent callback function  must be callable");
        return -1;
    }

    if(!PyCallable_Check(fn_udp_recv_cb)){
        PyErr_SetString(PyExc_TypeError,"udp recv callback function  must be callable");
        return -1;
    }

    Py_XDECREF(ip_sent_cb);
    Py_XDECREF(udp_recv_cb);

    ip_sent_cb=fn_ip_sent_cb;
    udp_recv_cb=fn_udp_recv_cb;

    Py_INCREF(ip_sent_cb);
    Py_INCREF(udp_recv_cb);   

    return 0;
}

static PyObject *
proxy_mtu_set(PyObject *self,PyObject *args)
{
    int mtu,is_ipv6;
    if(!PyArg_ParseTuple(args,"ip",&mtu,&is_ipv6)) return NULL;

    if(mtu<576 || mtu > 9000){
        PyErr_SetString(PyExc_ValueError,"mtu must be 576 to 9000");
        return NULL;
    }

    if(is_ipv6) ipv6_mtu_set(mtu);
    else ip_mtu_set(mtu);

    Py_RETURN_NONE;
}

/// 处理接收到的网络数据包
static PyObject *
proxy_netpkt_handle(PyObject *self,PyObject *args)
{
    const char *s,*id;
    Py_ssize_t size,id_size;
    struct mbuf *m;
    int from;

    if(!PyArg_ParseTuple(args,"y#y#i",&id,&id_size,&s,&size,&from)) return NULL;
    if(size<21){
        STDERR("wrong IP data format\r\n");
        Py_RETURN_FALSE;
    }

    m=mbuf_get();
    if(NULL==m){
        STDERR("cannot get mbuf\r\n");
        Py_RETURN_FALSE;
    }

    m->begin=m->offset=MBUF_BEGIN;
    m->end=m->tail=m->begin+size;

    m->from=from;

    memcpy(m->data+m->offset,s,size);
    memcpy(m->id,id,16);

    ip_handle(m);

    Py_RETURN_TRUE;
}

/// 发送UDP数据包
static PyObject *
proxy_udp_send(PyObject *self,PyObject *args)
{
    unsigned char *saddr,*daddr;
    char *data;
    Py_ssize_t saddr_s,daddr_s,data_s;
    unsigned short sport,dport,csum_coverage;
    int is_ipv6,is_udplite;

    if(!PyArg_ParseTuple(args,"y#y#HHppHy#",&saddr,&saddr_s,&daddr,&daddr_s,&sport,&dport,&is_udplite,&is_ipv6,&csum_coverage,&data,&data_s)) return NULL;

    if(is_ipv6 && (saddr_s!=16 || daddr_s!=16)){
        PyErr_SetString(PyExc_ValueError,"wrong IPv6 source address or destination address value");
        return NULL;
    }

    if(!is_ipv6 && (saddr_s!=4 || daddr_s!=4)){
        PyErr_SetString(PyExc_ValueError,"wrong IP source address or destination address value");
        return NULL;
    }

    udp_send(saddr,daddr,sport,dport,is_udplite,is_ipv6,csum_coverage,data,data_s);
    Py_RETURN_NONE;
}

/// 打开tun设备
static PyObject *
proxy_tun_open(PyObject *self,PyObject *args)
{
    const char *name;
    char new_name[512];
    int fd;

    if(!PyArg_ParseTuple(args,"s",&name)) return NULL;
    
    strcpy(new_name,name);

    fd=tundev_create(new_name);
    if(fd<0){
        return PyLong_FromLong(fd);
    }

    tundev_up(name);
    tundev_set_nonblocking(fd);

    return PyLong_FromLong(fd);
}

/// 关闭tun设备
static PyObject *
proxy_tun_close(PyObject *self,PyObject *args)
{
    const char *name;
    int fd;

    if(!PyArg_ParseTuple(args,"is",&fd,&name)) return NULL;

    tundev_close(fd,name);

    Py_RETURN_NONE;
}

static PyObject *
proxy_loop(PyObject *self,PyObject *args)
{
    sysloop_do();

    if(qos_have_data()){
        Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

static PyObject *
proxy_ipalloc_subnet_set(PyObject *self,PyObject *args)
{
    const char *s;
    unsigned char prefix;
    unsigned char buf[256],new_buf[256];
    int is_ipv6;

    if(!PyArg_ParseTuple(args,"sBp",&s,&prefix,&is_ipv6)) return NULL;

    if(is_ipv6 && prefix>64){
        STDERR("IPv6 prefix max must be 64\r\n");
        Py_RETURN_FALSE;
    }

    if(!is_ipv6 && prefix>24){
        STDERR("IP prefix max must be 24\r\n");
        Py_RETURN_FALSE;
    }

    if(is_ipv6){
        inet_pton(AF_INET6,s,buf);
    }else{
        inet_pton(AF_INET,s,buf);
    }

    subnet_calc_with_prefix(buf,prefix,is_ipv6,new_buf);
    ipalloc_subnet_set(new_buf,prefix,is_ipv6);

    Py_RETURN_TRUE;
}

static PyObject *
proxy_clog_set(PyObject *self,PyObject *args)
{
    const char *stdout_path,*stderr_path;

    if(!PyArg_ParseTuple(args,"ss",&stdout_path,&stderr_path)) return NULL;

    if(freopen(stdout_path,"a+",stdout)==NULL){
        STDERR("cannot set stdout\r\n");
        return NULL;
    }

    if(freopen(stderr_path,"a+",stderr)==NULL){
        STDERR("cannot set stderr\r\n");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyMemberDef proxy_members[]={
    {NULL}
};

static PyMethodDef proxy_methods[]={
    {"mtu_set",(PyCFunction)proxy_mtu_set,METH_VARARGS,"set mtu for IP and IPv6"},

    {"netpkt_handle",(PyCFunction)proxy_netpkt_handle,METH_VARARGS,"handle ip data packet"},

    {"udp_send",(PyCFunction)proxy_udp_send,METH_VARARGS,"udp data send"},

    {"tun_open",(PyCFunction)proxy_tun_open,METH_VARARGS,"open tun device"},
    {"tun_close",(PyCFunction)proxy_tun_close,METH_VARARGS,"close tun device"},

    {"loop",(PyCFunction)proxy_loop,METH_NOARGS,"do loop"},

    {"ipalloc_subnet_set",(PyCFunction)proxy_ipalloc_subnet_set,METH_VARARGS,"set ipalloc subnet"},

    {"clog_set",(PyCFunction)proxy_clog_set,METH_VARARGS,"set C language log path"},
    
    {NULL,NULL,0,NULL}
};

static PyTypeObject proxy_type={
    PyVarObject_HEAD_INIT(NULL,0)
    .tp_name="proxy.proxy",
    .tp_doc="python proxy helper library",
    .tp_basicsize=sizeof(proxy_object),
    .tp_itemsize=0,
    .tp_flags=Py_TPFLAGS_DEFAULT,
    .tp_new=proxy_new,
    .tp_init=(initproc)proxy_init,
    .tp_dealloc=(destructor)proxy_dealloc,
    .tp_members=proxy_members,
    .tp_methods=proxy_methods
};

static struct PyModuleDef proxy_module={
    PyModuleDef_HEAD_INIT,
    "proxy",
    NULL,
    -1,
    proxy_methods
};

PyMODINIT_FUNC
PyInit_proxy(void){
    PyObject *m;
    const char *const_names[] = {
        "FROM_LAN",
        "FROM_WAN"
	};

	const int const_values[] = {
        MBUF_FROM_LAN,
        MBUF_FROM_WAN
	};
    
    int const_count = sizeof(const_names) / sizeof(NULL);

    if(PyType_Ready(&proxy_type) < 0) return NULL;

    m=PyModule_Create(&proxy_module);
    if(NULL==m) return NULL;

    for (int n = 0; n < const_count; n++) {
		if (PyModule_AddIntConstant(m, const_names[n], const_values[n]) < 0) return NULL;
	}

    Py_INCREF(&proxy_type);
    if(PyModule_AddObject(m,"proxy",(PyObject *)&proxy_type)<0){
        Py_DECREF(&proxy_type);
        Py_DECREF(m);
        return NULL;
    }
    
    return m;
}