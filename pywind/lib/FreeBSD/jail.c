#include <Python.h>
#include<structmember.h>

#include<sys/param.h>
#include<sys/jail.h>
#include<sys/uio.h>
#include<netinet/in.h>

static PyObject *
jail_jail(PyObject *self,PyObject *args)
{
    struct jail j;
    PyObject *ip4_list;
    PyObject *ip6_list;
    unsigned int ip4s=0;
    unsigned int ip6s=0;

    // 最大支持256个IP地址
    struct in_addr[256];
    struct in6_addr[256];

    Py_ssize_t ip4_ss,ip6_ss;

    bzero(&j,sizeof(struct jail));

    if(!PyArg_ParseTuple(args,"IsssOO",&(j.version),&(j.path),&(j.hostname),&(j.jailname),&ip4_list,&ip6_list)){
        return NULL;
    }

    if(!PyList_Check(ip4_list) || !PyList_Check(ip6_list)){
        return NULL;
    }
    
    ip4_ss=PyList_GET_SIZE(ip4_list);
    ip6_ss=PyList_GET_SIZE(ip6_list);

    if(ip4_ss>256 || ip6_ss>256){
        return NULL;
    }

    





    return NULL;
}

static PyObject *
jail_jail_attach(PyObject *self,PyObject *args)
{
    return NULL;
}

static PyObject *
jail_jail_remove(PyObject *self,PyObject *args)
{
    return NULL;
}


static PyObject *
jail_jail_get(PyObject *self,PyObject *args)
{
    return NULL;
}

static PyObject *
jail_jail_set(PyObject *self,PyObject *args)
{
    return NULL;
}


static PyMethodDef JailMethods[] = {
    {"jail",jail_jail,METH_VARARGS,"jail"},
    {"jail_attach",jail_jail_attach,METH_VARARGS,"jail_attach"},
    {"jail_remove",jail_jail_remove,METH_VARARGS,"jail_remove"},
    {"jail_get",jail_jail_get,METH_VARARGS,"jail_get"},
    {"jail_set",jail_jail_set,METH_VARARGS,"jail_set"},
    {NULL}
};

static struct PyModuleDef JailModule={
	PyModuleDef_HEAD_INIT,
	"jail",
	NULL,
	-1,
	JailMethods
};

PyMODINIT_FUNC
PyInit_jail(void)
{
    PyObject *m;

    const char *names[]={
        "JAIL_CREATE",
        "JAIL_UPDATE",
        "JAIL_ATTACH",
        "JAIL_DYING",
        "JAIL_API_VERSION"
    };

    const int values[]={
        JAIL_CREATE,
        JAIL_UPDATE,
        JAIL_ATTACH,
        JAIL_DYING,
        JAIL_API_VERSION
    };

    int const_count = sizeof(names) / sizeof(NULL);

    m = PyModule_Create(&JailModule);

	if (NULL == m) return NULL;

	for (int n = 0; n < const_count; n++) {
		if (PyModule_AddIntConstant(m, names[n], values[n]) < 0)  return NULL;
	}

	return m;
}