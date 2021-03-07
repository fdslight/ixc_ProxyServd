#include<Python.h>
#include<sys/ipc.h>
#include<sys/shm.h>
#include<structmember.h>


typedef struct {
    PyObject_HEAD
    char *shmaddr;
    int shmid;
    int errcode;
    struct shmid_ds buf[0];
} shmoper_object;


static PyObject *
shm_memnew(PyObject *self,PyObject *args)
{
    key_t key;
    size_t size;
    int shmflg,rt,shared_id;

    /** for 32bit system **/
    if(4==sizeof(NULL)){
        rt=PyArg_ParseTuple(args,"kki",&key,&size,&shmflg);
    }else{
        rt=PyArg_ParseTuple(args,"kKi",&key,&size,&shmflg);
    }

    if(!rt) return NULL;
    
    shared_id=shmget(key,size,shmflg);
    if(shared_id<0) return Py_BuildValue("Oi",Py_False,errno);

    return Py_BuildValue("Oi",Py_True,shared_id);
}

static PyObject *
shm_memdel(PyObject *self,PyObject *args)
{
    struct shmid_ds buf;
    int shmid=0;

    if(!PyArg_ParseTuple(args,"i",&shmid)) return NULL;

    return PyLong_FromLong(shmctl(shmid,IPC_RMID,&buf));
}

static PyObject *
shm_shmdt(PyObject *self,PyObject *args)
{
    shmoper_object *object=(shmoper_object *)self;

    return PyLong_FromLong(shmdt(object->shmaddr));
}

static PyObject *
shm_shmctl(PyObject *self,PyObject *args)
{
    shmoper_object *object=(shmoper_object *)self;
    int rt=0,cmd=0;

    if(!PyArg_ParseTuple(args,"i",&cmd)) return NULL;
    rt=shmctl(object->shmid,cmd,object->buf);

    return PyLong_FromLong(rt);
}

static PyObject *
shm_write(PyObject *self,PyObject *args)
{
    const char *sts;
    char *tmp;
    int size;
    unsigned int offset;

    shmoper_object *object=(shmoper_object *)self;

    if(!PyArg_ParseTuple(args,"y#I",&sts,&size,&offset)) return NULL;

    tmp=object->shmaddr;

    tmp+=offset;
    memcpy(tmp,sts,size);

    Py_RETURN_NONE;
}

static PyObject *
shm_read(PyObject *self,PyObject *args)
{
    unsigned int offset=0,size=0;
    shmoper_object *object=(shmoper_object *)self;
    char *tmpaddr=object->shmaddr;

    if(!PyArg_ParseTuple(args,"II",&offset,&size)) return NULL;

    tmpaddr+=offset;

    return Py_BuildValue("y#",tmpaddr,size);
}

static void 
shm_dealloc(shmoper_object *self)
{
    shmoper_object *object=(shmoper_object *)self;

    if(NULL!=object->shmaddr) shmdt(object->shmaddr);

    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
shm_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    shmoper_object *self=NULL;
    self=(shmoper_object *)type->tp_alloc(type,0);

    return (PyObject *)self;
}

static PyObject *
shm_shmat(PyObject *self,PyObject *args)
{
    int shmid=0,shmflg=0;
    shmoper_object *object=NULL;
    
    if(!PyArg_ParseTuple(args,"ii",&shmid,&shmflg)) return NULL;

    object=(shmoper_object *)self;
    object->shmaddr=shmat(shmid,NULL,shmflg);

    if(-1==(int)(object->shmaddr)){
        object->errcode=errno;
        Py_RETURN_FALSE;
    } 

    Py_RETURN_TRUE;
}

static int
shm_init(shmoper_object *self,PyObject *args,PyObject *kwds)
{
    shmoper_object *object=(shmoper_object *)self;
    object->shmaddr=NULL;

    return 0;
}

static PyObject *
shm_shmid_ds_shm_segsz(PyObject *self)
{
    shmoper_object *object=(shmoper_object *)self; 

    return PyLong_FromLong(object->buf->shm_segsz);
}

static PyObject *
shm_shmid_ds_shm_cpid(PyObject *self)
{
    shmoper_object *object=(shmoper_object *)self; 

    return Py_BuildValue("B",object->buf->shm_cpid);
}

static PyObject *
shm_shmid_ds_shm_lpid(PyObject *self)
{
    shmoper_object *object=(shmoper_object *)self; 

    return Py_BuildValue("B",object->buf->shm_lpid);
}

static PyObject *
shm_shmid_ds_shm_nattch(PyObject *self)
{
    shmoper_object *object=(shmoper_object *)self; 

    return Py_BuildValue("h",object->buf->shm_nattch);
}

static PyMethodDef shmoper_Methods[]={
    {"at",(PyCFunction)shm_shmat,METH_VARARGS,"map memory to current process"},
    {"ctl",(PyCFunction)shm_shmctl,METH_VARARGS,"control memory"},
    {"dt",(PyCFunction)shm_shmdt,METH_NOARGS,"No map memory"},
    {"read",(PyCFunction)shm_read,METH_VARARGS,"read memory data"},
    {"write",(PyCFunction)shm_write,METH_VARARGS,"write data to memory"},
    {"ds_shm_segsz",(PyCFunction)shm_shmid_ds_shm_segsz,METH_NOARGS,"size of segment (bytes)"},
    {"ds_shm_cpid",(PyCFunction)shm_shmid_ds_shm_cpid,METH_NOARGS,"pid of creator"},
    {"ds_shm_lpid",(PyCFunction)shm_shmid_ds_shm_lpid,METH_NOARGS,"pid of last operator"},
    {"ds_shm_nattch",(PyCFunction)shm_shmid_ds_shm_nattch,METH_NOARGS,"no. of current attaches"},
    {NULL,NULL,0,NULL}
};

static PyMemberDef shmoper_members[]={
    {"errcode",T_INT,offsetof(shmoper_object,errcode),0,"error code"},
    {NULL}
};

static PyMethodDef shm_methods[]={
    {"memnew",(PyCFunction)shm_memnew,METH_VARARGS,"create new shared memory"},
    {"memdel",(PyCFunction)shm_memdel,METH_VARARGS,"delete shared memory"},
    {NULL,NULL,0,NULL}
};

static PyTypeObject shmoperType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "shm.shmoper",             /* tp_name */
    sizeof(shmoper_object),             /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)shm_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "shared memory manager objects",           /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    shmoper_Methods,             /* tp_methods */
    shmoper_members,                   /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)shm_init,      /* tp_init */
    0,                         /* tp_alloc */
    shm_new,                 /* tp_new */
};

static PyModuleDef shmmodule = {
    PyModuleDef_HEAD_INIT,
    "shm",
    "share memory",
    -1,
    shm_methods
};

PyMODINIT_FUNC
PyInit_shm(void)
{
    PyObject* m;
    
    const char *names[]={
        "IPC_PRIVATE",
        "IPC_CREATE",
        "IPC_EXCL",
        /**IPC CMD**/
        "IPC_STAT",
        /** error code **/
        "EACCES",
        "EFAULT",
        "EIDRM",
        "EINVAL",
        "EPERM",
        "EEXIST",
        "ENOSPC",
        "ENOENT",
        "ENOMEM"
    };

    int values[]={
        IPC_PRIVATE,
        IPC_CREAT,
        IPC_EXCL,
        /** IPC CMD **/
        IPC_STAT,
        /** error code **/
        EACCES,
        EFAULT,
        EIDRM,
        EINVAL,
        EPERM,
        EEXIST,
        ENOSPC,
        ENOENT,
        ENOMEM
    };

    size_t count=sizeof(values)/sizeof(int);

    shmoperType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&shmoperType) < 0)
        return NULL;

    m = PyModule_Create(&shmmodule);
    if (m == NULL) return NULL;
    
    
    for(size_t n=0;n<count;n++){
        if(PyModule_AddIntConstant(m,names[n],values[n])<0) return NULL;
    }

    Py_INCREF(&shmoperType);
    PyModule_AddObject(m, "shmoper", (PyObject *)&shmoperType);
    return m;
}



