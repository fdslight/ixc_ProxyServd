#!/bin/sh

cc test_ev.c ../map.c ../timer.c ../ev/ev.c ../ev/ev_select.c ../ev/ev_epoll.c ../ev/rpc.c -g -Wall -DDEBUG
./a.out