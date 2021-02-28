//
// Created by KaiMei on 2019/9/8.
//

#ifndef PFILE_H
#define PFILE_H

#include<sys/types.h>

void pfile_write(const char *path,pid_t pid);
pid_t pfile_read(const char *path);


#endif //NETBUS_PFILE_H
