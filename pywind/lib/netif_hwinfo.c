#include <Python.h>
#include<structmember.h>
#include "../clib/netif/hwinfo.h"

static PyObject *
netif_hwinfo_hwaddr_get(PyObject *self,PyObject *args)
{
    const char *if_name;
    unsigned char buf[1024];
    int rs=0;

    if (!PyArg_ParseTuple(args, "s", &if_name)) return NULL;

    rs=hwinfo_get(if_name,buf);

    if(rs<0){
        Py_RETURN_NONE;
    }

    return Py_BuildValue("y#",buf,6);
}

static PyMethodDef netif_hwinfo_methods[] = {
    {"hwaddr_get",netif_hwinfo_hwaddr_get,METH_VARARGS,"get network card hardware address"},
    {NULL,NULL,0,NULL}
};

static struct PyModuleDef utilsmodule = {
	PyModuleDef_HEAD_INIT,
	"netif_hwinfo",
	NULL,
	-1,
	netif_hwinfo_methods,
};

PyMODINIT_FUNC
PyInit_netif_hwinfo(void)
{
    PyObject *m = PyModule_Create(&utilsmodule);

	if (NULL == m) return NULL;

    return m;
}