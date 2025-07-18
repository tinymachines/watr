#!/bin/bash

#gcc -o wifi-monitor-setup wifi-monitor-setup.c $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0)
#gcc -o wifi-monitor-setup wifi-monitor-setup.c $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0) -Wall
#gcc -o wifi-monitor-setup wifi-monitor-setup.c $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0) -Wall
gcc -o wifi-monitor-setup wifi-monitor-setup.c $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0) -Wall
