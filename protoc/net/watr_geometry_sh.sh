#!/bin/bash

# WATR WiFi Geometry-Aware Node Launcher

source ${WATR_ROOT}/watr-header.sh

# Additional geometry-specific environment variables
WATR_LOCATION="${WATR_LOCATION:-Unknown-Location}"
WATR_SCAN_INTERVAL="${WATR_SCAN_INTERVAL:-180}"

echo "🌐📍 Starting Geometry-Aware WATR Node"
echo "   Device: $WATR_DEVICE"
echo "   Address: $WATR_ADDR"
echo "   Name: $WATR_NAME"
echo "   Location: $WATR_LOCATION"
echo "   Model: $WATR_LLM"
echo "   Scan Interval: ${WATR_SCAN_INTERVAL}s"

sudo -E PYTHONPATH=".:${WATR_ROOT}/scapy" \
    $(which python) logged_wifi_geometry_main.py \
    ${WATR_DEVICE} ${WATR_ADDR} "${WATR_NAME}" "${WATR_LOCATION}" "${WATR_LLM}" "${WATR_LOGLEVEL:-INFO}"