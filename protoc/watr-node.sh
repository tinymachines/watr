#/bin/bash

source ${WATR_ROOT}/watr-header.sh
sudo -E PYTHONPATH=".:${WATR_ROOT}/scapy" $(which python) WATRNode.py ${WATR_DEVICE} ${WATR_ADDR}
