#!/bin/bash

WATR_ADDR=$(iw dev \
	| xargs \
	| sed -e 's/phy/\nphy/g' \
	| grep monitor \
	| grep -oP "addr \K([0-9a-f:]*)")

set WATR_ADDR="${WATR_ADDR}"
export WATR_ADDR="${WATR_ADDR}"
