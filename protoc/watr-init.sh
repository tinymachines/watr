#!/bin/bash

COMMAND="${1}"

source ${WATR_ROOT}/watr-header.sh
source ${WATR_ROOT}/watr-config.sh

function get_monitor_device() {
	local DEVICE=( $( ${WATR_ROOT}/wifi-monitor-check | grep MONITOR | head -n1) )
	if [[ ! -z ${DEVICE} ]]; then
		read -ra IFACE<<<$(airmon-ng | grep "${DEVICE}")
		local IFACE="${IFACE[1]}"
		echo "${IFACE}"
	fi
}

WATR_DEVICE=$(get_monitor_device)
# NEED A TEST HERE TO SEE IF DEVICE
# IS ALREADY IN MONITOR MODE
if [[ ! -z ${WATR_DEVICE} ]]; then
	init_main
	export WATR_DEVICE="${WATR_DEVICE}"
	set WATR_DEVICE="${WATR_DEVICE}"
fi
