#!/bin/bash

gcc -o wifi-monitor-check wifi-monitor-check.c -I/usr/include/libnl3 $(pkg-config --libs libnl-3.0 libnl-genl-3.0)
