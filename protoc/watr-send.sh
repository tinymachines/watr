#/bin/bash

source ${WATR_ROOT}/watr-header.sh

sudo -E PYTHONPATH=".:${WATR_ROOT}/scapy" $(which python) ./custom.py send ${WATR_DEVICE}
