#ifndef __DEBUG_H
#define __DEBUG_H

#include "../../../pywind/clib/debug.h"

#define PRINT_IP(TEXT,X) DBG("%s %d.%d.%d.%d\r\n",TEXT,X[0],X[1],X[2],X[3])
#define PRINT_IP6(TEXT,X) DBG("%s %X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X\r\n",TEXT,X[0],X[1],X[2],X[3],X[4],X[5],X[6],X[7],X[8],X[9],X[10],X[11],X[12],X[13],X[14],X[15])

#endif