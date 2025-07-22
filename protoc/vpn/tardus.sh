#!/bin/bash

cd /home/bisenbek/spidr/scripts/networking/vpn

while read -r ROW; do
	ORIG="${ROW}"
	ROW=$(basename "${ROW}")
	IFS='-' read -ra PARTS<<<${ROW}

	COUNTRY=$(echo "${PARTS[0]}" | tr "[[:lower:]]" "[[:upper:]]")
	STATE=$(echo "${PARTS[1]}" | tr "[[:lower:]]" "[[:upper:]]")

	echo "${ORIG}	${ROW}	${COUNTRY}	${STATE}"

done<<<$(find ./conf -type f | grep -E ".ovpn$")
