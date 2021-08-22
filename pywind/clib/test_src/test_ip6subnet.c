#include<stdio.h>
#include<arpa/inet.h>
#include<string.h>

#include "../netutils.h"


int main(int arc,char *argv[])
{
    const char *ip="2607:f8b0:4007:800::2004";
    unsigned char n_ip[16];
    unsigned char sub[16];
    unsigned char msk[16];

    inet_pton(AF_INET6,ip,n_ip);

    msk_calc(128,1,msk);
    subnet_calc_with_msk(n_ip,msk,1,sub);

    printf("%d\r\n",memcmp(sub,n_ip,16));
    
}