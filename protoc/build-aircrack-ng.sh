#!/bin/bash

cd ./aircrack-ng

make clean && ./autogen.sh && ./configure && make && sudo make install && sudo ldconfig

cd ..
