#!/bin/bash

USER="bisenbek"
SERIAL=$(cat /proc/cpuinfo | grep Serial | while IFS=":" read -ra ROW; do echo "${ROW[-1]}"; done | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
SERIAL="${SERIAL:11:15}"
HOSTNAME="meatball${SERIAL}"
MEATPATH="${HOME}/.meatball"

source ~/.bashrc

mkdir ${MEATPATH} &> /dev/null

function set_host() {

  mv ${MEATPATH}/hosts.backup ${MEATPATH}/hosts.prev
  cp /etc/hosts ${MEATPATH}/hosts.backup
  cat /etc/hosts \
    | grep -Ev "^127.0.0.1[[:space:]]" \
    | sudo tee ${MEATPATH}/hosts &> /dev/null

  echo -e "127.0.0.1	localhost\n127.0.0.1	${HOSTNAME}\n127.0.0.1	${HOSTNAME}.lan\n127.0.0.1	${HOSTNAME}.local\n" \
    | sudo tee -a ${MEATPATH}/hosts &> /dev/null

  cat ${MEATPATH}/hosts | sed -r '/^\s*$/d' | tr -s '\t' sudo tee /etc/hosts

  sudo hostnamectl hostname ${HOSTNAME}
  sudo hostnamectl chassis embedded
  sudo hostnamectl deployment development
  sudo hostnamectl location garage

}

function configure_wifi() {

	[[ -z $(/sbin/iwgetid) ]] && {
        	sudo nmcli radio wifi on
        	sudo nmcli dev wifi connect meatball password "11111111"
	}
}

function monitor() {
	
	[[ ! -z $(/sbin/ifconfig | grep mon0) ]] && return

	local PHY=0
	while (( PHY<10 )); do
		local RESULT=$(sudo iw phy phy${PHY} interface add mon0 type monitor || echo "${PHY} FAIL::MON NOT SUPPORTED")
		echo "${RESULT}"
		[[ -z $(echo "${RESULT}" | grep -i fail) ]] && {
			sudo iw dev mon0 set freq 2412
			sudo ifconfig mon0 up
			break
		}
		PHY=$(( PHY+1 ))
		sleep 1
	done
}

function find_device () {

	while read -r ROW; do
		if [[ -f "${ROW}"/product ]]; then
			local PRODUCT="$(cat ${ROW}/product)"
			if [[ ! -z $(echo "${PRODUCT}" | grep -iE 'wireless|wlan|wifi') ]]; then
				echo "$(basename ${ROW})"
			fi
			
		fi
	done<<<$(find /sys/bus/usb/drivers/usb/ | grep -E '.*/[0-9][-]{0,1}[0-9]{0,1}')
}

function configure_monitor () {

	[[ ! -z $(/sbin/ifconfig | grep mon0) ]] && return
	local COUNT=0

	while (( COUNT < 3 )); do

		read -ra ROW <<<$(sudo lsusb | grep -i 'wireless')

		local USBID="${ROW[5]}"
		local PHY=( $(./wifi-monitor-check | grep MONITOR) )

		echo "Adapter => ${USBID}	Device => ${PHY}"

		if [[ -z ${PHY} ]] && [[ ! -z ${USBID} ]]; then

			local BUSID="$(find_device)"
			echo "Resetting ${BUSID} / ${USBID}"

			sudo usbreset "${USBID}"

			if [[ ! -z ${BUSID} ]]; then
				echo "${BUSID}" | sudo tee /sys/bus/usb/drivers/usb/unbind
				echo "${BUSID}" | sudo tee /sys/bus/usb/drivers/usb/bind
			fi

		elif [[ -z ${PHY} ]] && [[ -z ${USBID} ]]; then
			sudo ./wifi-monitor-setup ${PHY}
		else
			break
		fi
		local COUNT=$(( COUNT+1 ))
		sleep 3 
	done
}

function configure_firewall() {
	if [[ -z $(sudo ufw status verbose | grep 'allow (incoming), allow (outgoing)') ]] || [[ ${1}=='allow' ]] ; then
		echo "OPENING FIREWALL"
		sudo ufw default allow incoming
		sudo ufw default allow outgoing
	else
		echo "CLOSING FIREWALL"
		sudo ufw default deny incoming
		sudo ufw default allow outgoing
	fi
}

if [[ ! -z ${1} ]]; then
	${1} "${2}"
else
	#setup_host
	#configure_wifi
	configure_monitor
fi
