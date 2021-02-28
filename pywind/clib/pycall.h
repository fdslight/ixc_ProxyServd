#include<Python.h>
#ifndef __PYCALL_H
#define __PYCALL_H

int py_add_path(const char *path)
{
    size_t length=strlen(path);
    char buf[2048];
    char *tmp=buf;

    const char *a="import sys\r\n";
    const char *b="sys.path.append('";
    const char *c="')\r\n";

    if(length>1024) return -1;

    bzero(buf,2048);

    memcpy(tmp,a,12);
    tmp+=12;
    memcpy(tmp,b,17);
    tmp+=17;
    memcpy(tmp,path,length);
    tmp+=length;
    memcpy(tmp,c,4);
    
    PyRun_SimpleString(buf);
    return 0;
}


PyObject *py_module_load(const char *name)
{
    PyObject *pName,*pModule;

    pName=PyUnicode_DecodeFSDefault(name);
    
    if(!pName) return NULL;

    pModule=PyImport_Import(pName);

    Py_DECREF(pName);
    if(!pModule) return NULL;

    return pModule;
}

PyObject *py_func_call(PyObject *module,const char *func_name,PyObject **args,size_t arg_size)
{
    PyObject *pArgs=NULL,*pValue,*pFunc;

    pFunc=PyObject_GetAttrString(module,func_name);
    
    if(!pFunc || !PyCallable_Check(pFunc)) return NULL;

    pArgs=PyTuple_New(arg_size);

    for(int n=0;n<arg_size;n++){
        PyTuple_SetItem(pArgs, n, args[n]);
    }

    pValue=PyObject_CallObject(pFunc,pArgs);

    for(int n=0;n<arg_size;n++){
        Py_DECREF(args[n]);
    }

    Py_DECREF(pArgs);
    Py_DECREF(pFunc);

    return pValue;
}

void py_module_unload(PyObject *module)
{
    Py_DECREF(module);
}


#endif