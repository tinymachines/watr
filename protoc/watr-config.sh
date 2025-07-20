#!/bin/bash

source ${WATR_ROOT}/watr-header.sh

function hw_reset() {
	
	read -ra PARTS<<<$(lsusb | grep -iE "realtek|801[.]11" | sed --expression "s/[^0-9 ]/ /g")

	sudo usbreset ${PARTS[0]}/${PARTS[1]}
        sudo raspi-config nonint do_wifi_country US
        sudo rfkill unblock all
        #sudo airmon-ng check kill
        #sudo systemctl restart NetworkManager
}

function get_monitor_device() {
	local DEVICE=( $( ${WATR_ROOT}/wifi-monitor-check | grep MONITOR | head -n1) )
	if [[ ! -z ${DEVICE} ]]; then
		read -ra IFACE<<<$(airmon-ng | grep "${DEVICE}")
		local IFACE="${IFACE[1]}"
		echo "${IFACE}"
	fi
}

function init_mon() {

	local IFACE="${1}"

	if [[ ! -z "${IFACE}" ]]; then
		sudo ifconfig "${IFACE}" down
		sudo iwconfig "${IFACE}" mode monitor
		sudo ifconfig "${IFACE}" up
		sudo iwconfig "${IFACE}" chan 6
		sudo iwconfig "${IFACE}"
	else
		:
	fi

	# This does not work	
	#sudo iw dev ${DEVICE} interface add mon0 type monitor
	#sudo ip link set mon0 up
	#sudo iw dev mon0 set channel 6
	#sudo ./wifi-monitor-setup "${DEVICE}"
}

function test_aireplay() {
	sudo aireplay-ng --test "${1}"
}

function test_scapy() {
	sudo -E PYTHONPATH=".:.${WATR_ROOT}/scapy" $(which python) ${WATR_ROOT}/custom.py send
}

function  init_main() {
	hw_reset
	init_mon "${WATR_DEVICE}"
}

#DEVICE=$(get_monitor_device)
#if [[ -z ${DEVICE} ]]; then
#	echo "NO DEVICE SPECIFIED"
#fi

