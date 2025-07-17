#!/bin/bash

sudo tcpdump -vvv -n -i mon0 -s0 -X -c 1000
