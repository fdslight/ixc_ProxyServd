#ifndef EV_SELECT_H
#define EV_SELECT_H

#include "ev.h"

struct ev_select{
	struct ev_set *ev_set;
	int fd_max;
};

int ev_select_init(struct ev_set *ev_set);
void ev_select_uninit(struct ev_set *ev_set);

#endif