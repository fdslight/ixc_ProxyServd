#ifndef IP6_UNFRAG_H
#define IP6_UNFRAG_H
#include "mbuf.h"

#include "../../../pywind/clib/map.h"

#define IP6UNFRAG_KEYSIZE 36
struct ip6unfrag{
    struct map *m;
};

int ip6unfrag_init(void);
void ip6unfrag_uninit(void);

struct mbuf *ip6unfrag_add(struct mbuf *m);


#endif