#!/bin/bash

source ${WATR_ROOT}/watr-header.sh

function hw_reset() {

	local WATR_DEVICE="${1}"
	sudo ifconfig "${WATR_DEVICE}" down

	read -ra PARTS<<<$(lsusb | grep -iE "wireless|realtek|801[.]11" | sed --expression "s/[^0-9 ]/ /g")

	sudo usbreset ${PARTS[0]}/${PARTS[1]}
	sleep 5
        #sudo raspi-config nonint do_wifi_country US
        #sudo rfkill unblock all
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

	#local WATR_DEVICE="${1}"

	if [[ ! -z "${WATR_DEVICE}" ]]; then
		sudo ifconfig "${WATR_DEVICE}" down
		sudo iwconfig "${WATR_DEVICE}" mode monitor
		#sudo ifconfig "${WATR_DEVICE}" multicast
		sudo ifconfig "${WATR_DEVICE}" up
		#sudo iwconfig "${WATR_DEVICE}" txpower 15
		#sudo iwconfig "${WATR_DEVICE}" sens -80
		#sudo iwconfig "${WATR_DEVICE}" retry 16
		#sudo iwconfig "${WATR_DEVICE}" power off
		#sudo iwconfig "${WATR_DEVICE}" rate 2M
		sudo iwconfig "${WATR_DEVICE}" chan ${WATR_CHAN}
		#sudo iwconfig "${WATR_DEVICE}" rts ${WATR_RTS}
		#sudo iwconfig "${WATR_DEVICE}" frag 512
		#sudo iwconfig "${WATR_DEVICE}" modu auto
		sudo iwconfig "${WATR_DEVICE}"
	else
		:
	fi

	# This does not work	
	#sudo iw dev ${DEVICE} interface add mon0 type monitor
	#sudo ip link set mon0 up
	#sudo iw dev mon0 set channel 6
	#sudo ./wifi-monitor-setup "${DEVICE}"
}

function init_wifi() {
	
	if [[ ! -z ${WATR_WIFI} ]] && [[ ! -z ${WATR_SSID} ]] && [[ ! -z ${WATR_PASS}  ]]; then
		sudo ip link set ${WATR_WIFI} up
		sudo nmcli device wifi connect "${WATR_SSID}" password "${WATR_PASS}" ifname "${WATR_WIFI}"
	fi
}

function setchan() {
	sudo iwconfig ${WATR_DEVICE} chan ${WATR_CHAN}
	iw dev
}

function test_aireplay() {
	sudo aireplay-ng --test "${1}"
}

function test_scapy() {
	sudo -E PYTHONPATH=".:.${WATR_ROOT}/scapy" $(which python) ${WATR_ROOT}/custom.py send
}

function  init_main() {
	
	if [[ ${COMMAND} == "startup" ]]; then
		
		echo "RESET HW"
		hw_reset "${WATR_DEVICE}"

		echo "INIT MON"
		init_mon "${WATR_DEVICE}"

		echo "INIT WIFI"
		init_wifi

		echo "TEST MON"
		test_aireplay "${WATR_DEVICE}"

		setchan
	fi

	set WATR_ETH_INTERFACE="${WATR_ETH_INTERFACE:-eth0}"
	set WATR_ETH_NAME="${WATR_NAME:-EthNode}"
	set WATR_ETH_LLM="${WATR_LLM:-qwen3:0.6b}"
	set WATR_ETH_LOGLEVEL="${WATR_ETH_LOGLEVEL:-INFO}"

	export WATR_ETH_INTERFACE="${WATR_ETH_INTERFACE}"
	export WATR_ETH_NAME="${WATR_NAME}"
	export WATR_ETH_LLM="${WATR_LLM}"
	export WATR_ETH_LOGLEVEL="${WATR_ETH_LOGLEVEL}"


	set WATR_WIFI="${WATR_WIFI}"
	set WATR_SSID="${WATR_SSID}"
	export WATR_WIFI="${WATR_WIFI}"
	export WATR_SSID="${WATR_SSID}"
}

#DEVICE=$(get_monitor_device)
#if [[ -z ${DEVICE} ]]; then
#	echo "NO DEVICE SPECIFIED"
#fi

