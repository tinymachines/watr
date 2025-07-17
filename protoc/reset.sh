#!/bin/bash

function hw_reset() {
        sudo raspi-config nonint do_wifi_country US
        sudo rfkill unblock all
        sudo airmon-ng check kill
        sudo systemctl restart NetworkManager
}

function get_monitor_device() {
	local DEVICE=( $(./wifi-monitor-check | grep MONITOR | head -n1) )
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
		echo "NO DEVICE SPECIFIED"
	fi
		
	#sudo iw dev ${DEVICE} interface add mon0 type monitor
	#sudo ip link set mon0 up
	#sudo iw dev mon0 set channel 6
	#sudo ./wifi-monitor-setup "${DEVICE}"
}

function ap_test() {
	sudo aireplay-ng --test "${1}"
}

DEVICE=$(get_monitor_device)
hw_reset 
init_mon "${DEVICE}"
ap_test "${DEVICE}"

