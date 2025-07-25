#/bin/bash

source ${WATR_ROOT}/watr-header.sh
sudo -E PYTHONPATH=".:${WATR_ROOT}/scapy" $(which python) self_aware_main.py ${WATR_DEVICE} ${WATR_ADDR} "Alice"
