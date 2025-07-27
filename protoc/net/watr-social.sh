#/bin/bash

source ${WATR_ROOT}/watr-header.sh
sudo -E PYTHONPATH=".:${WATR_ROOT}/scapy" \
	$(which python) logged_llm_social_main.py \
	${WATR_DEVICE} ${WATR_ADDR} "${WATR_NAME}"
