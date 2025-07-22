#!/bin/bash

BASE="/home/bisenbek/watr/procs/vpn"
cd "${BASE}"

function connect() {
	CONNECT="$(./tardus.sh | sort | uniq | shuf | head -n1)"
	IFS="	" read -ra PARTS<<< "${CONNECT}"
	echo "${PARTS[@]}"
	sudo openvpn --config "${PARTS[0]}"
}

connect 2>&1 | tee ./logs/${HOSTNAME}.log
