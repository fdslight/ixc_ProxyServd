#ifndef IPUNFRAG_H
#define IPUNFRAG_H

#include "mbuf.h"

#include "../../../pywind/clib/map.h"

#define IPUNFRAG_KEYSIZE 10
struct ipunfrag{
    struct map *m;
};

int ipunfrag_init(void);
void ipunfrag_uninit(void);

struct mbuf *ipunfrag_add(struct mbuf *m);

#endif