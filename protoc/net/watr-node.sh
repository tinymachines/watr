#/bin/bash

source ${WATR_ROOT}/watr-header.sh
sudo -E PYTHONPATH=".:${WATR_ROOT}/scapy" $(which python) main.py ${WATR_DEVICE} ${WATR_ADDR}
