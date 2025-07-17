#!/bin/bash

function hw_reset() {
        sudo raspi-config nonint do_wifi_country XX
        sudo rfkill unblock all
        sudo ifconfig mon0 down
        sudo airmon-ng check kill
        sudo systemctl restart NetworkManager
	sudo ifconfig wlx4c0fc74a9773 down
	sudo iwconfig wlx4c0fc74a9773 mode monitor
	sudo iwconfig wlx4c0fc74a9773 chan 6
	sudo iwconfig wlx4c0fc74a9773
}

function init_mon() {
	local DEVICE=( $(./wifi-monitor-check | grep MONITOR | head -n1) )

	if [[ ! -z ${DEVICE} ]]; then
		sudo ./wifi-monitor-setup "${DEVICE}"
	fi

	#sudo iw dev ${DEVICE} interface add mon0 type monitor
	#sudo ip link set mon0 up
	#sudo iw dev mon0 set channel 6

}

function ap_test() {
	sudo aireplay-ng --test mon0
}
hw_reset
init_mon
ap_test

