#!/bin/sh

ps -ef | grep ixc_relay.py | awk '{print $2}' | xargs kill -9