#ifndef __DEBUG_H
#define __DEBUG_H

#include "../../../pywind/clib/debug.h"

#define PRINT_IP(TEXT,X) DBG("%s %d.%d.%d.%d\r\n",TEXT,X[0],X[1],X[2],X[3])
#define IXC_PRINT_IP6(TEXT,X) DBG("%s %X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X:%X\r\n",TEXT,X[0] & 0xff,X[1]&0xff,X[2]&0xff,X[3]&0xff,X[4]&0xff,X[5]&0xff,X[6]&0xff,X[7]&0xff,X[8]&0xff,X[9]&0xff,X[10]&0xff,X[11]&0xff,X[12]&0xff,X[13]&0xff,X[14]&0xff,X[15]&0xff)

#endif