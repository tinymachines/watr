#!/bin/bash

function hw_reset() {
	sudo ifconfig mon0 down
	sudo rfkill unblock all
	sudo airmon-ng check kill
	sudo systemctl restart NetworkManager
}

function init_mon() {
	local DEVICE=( $(./wifi-monitor-check | grep MONITOR | head -n1) )

	sudo iw dev ${DEVICE} interface add mon0 type monitor
	sudo ip link set mon0 up
	sudo iw dev mon0 set channel 6

	#if [[ ! -z ${DEVICE} ]]; then
	#	sudo ./wifi-monitor-setup "${DEVICE}"
	#fi
}

function ap_test() {
	sudo aireplay-ng --test mon0
}
ap_test
#hw_reset
#init_mon

