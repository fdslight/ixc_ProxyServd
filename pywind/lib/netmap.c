#define PY_SSIZE_T_CLEAN
#include<Python.h>
#include<structmember.h>

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "../../clib/debug.h"

#define NETMAP_WITH_LIBS
#include<net/netmap_user.h>



typedef struct{
    PyObject_HEAD
    struct nm_desc *netmap;
}Netmap;

static void
Netmap_dealloc(Netmap *self)
{
    if(NULL!=self->netmap) nm_close(self->netmap);
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
Netmap_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    Netmap *self;
    const char *name;
    struct nm_desc *netmap;
    char buf[1024];
    buf[0] = '\0';

    
    self=(Netmap *)type->tp_alloc(type,0);
    if(NULL==self) return NULL;

    self->netmap=NULL;

    if(!PyArg_ParseTuple(args,"s",&name)){
        Py_TYPE(self)->tp_free((PyObject *) self);
        return NULL;
    }

    strcat(buf, "netmap:");
    strcat(buf, name);

    netmap = nm_open(buf, NULL, 0, NULL);

    if(NULL==netmap){
        STDERR("cannot open %s\r\n",buf);
        Py_TYPE(self)->tp_free((PyObject *) self);
        return NULL;
    }

    self->netmap=netmap;
    return (PyObject *)self;    
}

static PyObject *
Netmap_set_as_nonblocking(Netmap *self,PyObject *args)
{
    int flags;

    flags=fcntl(self->netmap->fd,F_GETFL,0);
    fcntl(self->netmap->fd,F_SETFL,flags | O_NONBLOCK);

    Py_RETURN_NONE;
}

static PyObject *
Netmap_recv(Netmap *self,PyObject *args)
{
    unsigned char *buf;
    struct nm_desc *netmap = self->netmap;
    struct nm_pkthdr h;
    size_t size;

    buf=nm_nextpkt(netmap,&h);
    size=h.len;

    return Py_BuildValue("(y#,i)",buf,size,size);
}

/// 注意接收完毕后一定要调用此函数进行接收同步,不然接收缓冲不会刷新,每次收到的数据都是一样的
static PyObject *
Netmap_rx_sync(Netmap *self,PyObject *args)
{
    return PyLong_FromLong(ioctl(self->netmap->fd,NIOCRXSYNC,NULL));
}

static PyObject *
Netmap_send(Netmap *self,PyObject *args)
{
    struct nm_desc *netmap = self->netmap;
    const char *data;
    Py_ssize_t size;

    if(!PyArg_ParseTuple(args,"y#",&data,&size)) return NULL;

    return PyLong_FromLong(nm_inject(netmap,data,size));
}

static PyObject *
Netmap_close(Netmap *self,PyObject *args)
{
    nm_close(self->netmap);
    self->netmap=NULL;
    Py_RETURN_NONE;
}

static PyMethodDef Netmap_methods[]={
    {"set_as_nonblocking",(PyCFunction)Netmap_set_as_nonblocking,METH_NOARGS,"set as nonblocking"},
    {"recv",(PyCFunction)Netmap_recv,METH_NOARGS,"receive netmap data"},
    {"rx_sync",(PyCFunction)Netmap_rx_sync,METH_NOARGS,"receive sync"},
    {"send",(PyCFunction)Netmap_send,METH_VARARGS,"send data to netmap"},
    {"close",(PyCFunction)Netmap_close,METH_NOARGS,"close netmap file"},
    {NULL}
};

static PyTypeObject NetmapType={
    PyVarObject_HEAD_INIT(NULL,0)
    .tp_new=Netmap_new,
    .tp_dealloc=(destructor)Netmap_dealloc,
    .tp_name="netmap.Netmap",
    .tp_doc="netmap",
    .tp_basicsize=sizeof(Netmap),
    .tp_itemsize=0,
    .tp_flags=Py_TPFLAGS_DEFAULT,
    .tp_methods=Netmap_methods
};

static PyModuleDef netmapModule={
    PyModuleDef_HEAD_INIT,
    "netmap",
    "Netmap Class",
    -1,
    NULL
};

PyMODINIT_FUNC
PyInit_netmap(void)
{
    PyObject* m;

    if (PyType_Ready(&NetmapType) < 0) return NULL;

    m = PyModule_Create(&netmapModule);
    if (m == NULL) return NULL;

    Py_INCREF(&NetmapType);
    PyModule_AddObject(m, "Netmap", (PyObject *)&NetmapType);

    return m;
}




