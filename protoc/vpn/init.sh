#!/bin/bash

CHECK=$(ps aux | grep proton | grep openvpn | grep -v grep)
BASE="/home/bisenbek/spidr/scripts/networking/vpn"

[[ ! -f "${BASE}/init.sh" ]] && exit

echo "${HOSTNAME}	${BASE}"
cd "${BASE}"

sudo systemctl stop tinmac.proton.service
sudo cp ${BASE}/tinmac.openvpn.service /lib/systemd/system
sudo systemctl daemon-reload
sudo systemctl enable tinmac.openvpn.service
sudo systemctl restart tinmac.openvpn.service
