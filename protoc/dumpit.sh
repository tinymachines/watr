#!/bin/bash

sudo ./src/tcpdump/build/tcpdump -i ${WATR_DEVICE}  -e -vvv -XX -g -H -K -l --lengths -nN -# -O --print --direction=in -S 0 -tttt
#sudo tcpdump -vvv -n -i ${WATR_DEVICE} -s0 -X -c 1000
