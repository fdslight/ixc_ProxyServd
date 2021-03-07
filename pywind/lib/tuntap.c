#define PY_SSIZE_T_CLEAN
#include<Python.h>
#include<structmember.h>

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "../clib/netif/tuntap.h"

#include "../clib/debug.h"

typedef struct{
    PyObject_HEAD
    char name[256];
    int fd;
    int is_tap;
}Tuntap;

static void
Tuntap_dealloc(Tuntap *self)
{
    if(self->fd>0){
        if(self->is_tap){
            tapdev_close(self->fd,self->name);
        }else{
            tundev_close(self->fd,self->name);
        }
    }

    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
Tuntap_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    Tuntap *self;
    int is_tap;
    const char *name;

    self=(Tuntap *)type->tp_alloc(type,0);
    if(NULL==self) return NULL;
    self->fd=-1;

    if(!PyArg_ParseTuple(args,"sp",&name,&is_tap)){
        Py_TYPE(self)->tp_free((PyObject *) self);
        return NULL;
    }

    strcpy(self->name,name);

    if(is_tap){
        self->fd=tapdev_create(self->name);
        tapdev_up(self->name);
    }else{
        self->fd=tundev_create(self->name);
        tundev_up(self->name);
    }

    self->is_tap=is_tap;
    
    if(self->fd<0){
        STDERR("cannot create tuntap %s\r\n",self->name);
        Py_TYPE(self)->tp_free((PyObject *) self);
        return NULL;
    }

    return (PyObject *)self;
}

static PyObject *
Tuntap_set_as_nonblocking(Tuntap *self,PyObject *args)
{
    int flags;

    flags=fcntl(self->fd,F_GETFL,0);
    fcntl(self->fd,F_SETFL,flags | O_NONBLOCK);

    Py_RETURN_NONE;
}

static PyObject *
Tuntap_close(Tuntap *self,PyObject *args)
{
    if(self->is_tap){
        tapdev_close(self->fd,self->name);
    }else{
        tundev_close(self->fd,self->name);
    }

    self->fd=-1;
    Py_RETURN_NONE;
}

static PyObject *
Tuntap_info(Tuntap *self,PyObject *args)
{
    return Py_BuildValue("(i,s)",self->fd,self->name);
}

static PyMethodDef Tuntap_methods[]={
    {"set_as_nonblocking",(PyCFunction)Tuntap_set_as_nonblocking,METH_NOARGS,"set as nonblocking"},
    {"close",(PyCFunction)Tuntap_close,METH_NOARGS,"close tuntap"},
    {"info",(PyCFunction)Tuntap_info,METH_NOARGS,"tun device information"},
    {NULL}
};

static PyTypeObject TuntapType={
    PyVarObject_HEAD_INIT(NULL,0)
    .tp_new=Tuntap_new,
    .tp_dealloc=(destructor)Tuntap_dealloc,
    .tp_name="tuntap.Tuntap",
    .tp_doc="tuntap",
    .tp_basicsize=sizeof(Tuntap),
    .tp_itemsize=0,
    .tp_flags=Py_TPFLAGS_DEFAULT,
    .tp_methods=Tuntap_methods
};

static PyModuleDef tuntapModule={
    PyModuleDef_HEAD_INIT,
    "tuntap",
    "Tuntap Class",
    -1,
    NULL
};

PyMODINIT_FUNC
PyInit_tuntap(void)
{
    PyObject* m;

    if (PyType_Ready(&TuntapType) < 0) return NULL;

    m = PyModule_Create(&tuntapModule);
    if (m == NULL) return NULL;

    Py_INCREF(&TuntapType);
    PyModule_AddObject(m, "Tuntap", (PyObject *)&TuntapType);

    return m;
}

