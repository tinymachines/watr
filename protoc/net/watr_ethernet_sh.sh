#!/bin/bash

# WATR Ethernet Node Launcher

# Source header if it exists (for consistency with WiFi version)
if [ -f "${WATR_ROOT}/watr-header.sh" ]; then
    source "${WATR_ROOT}/watr-header.sh"
fi

# Default values
WATR_ETH_INTERFACE="${WATR_ETH_INTERFACE:-eth0}"
WATR_ETH_NAME="${WATR_ETH_NAME:-EthNode}"
WATR_ETH_LLM="${WATR_ETH_LLM:-qwen3:0.6b}"
WATR_ETH_LOGLEVEL="${WATR_ETH_LOGLEVEL:-INFO}"

# Check if running as root (required for raw sockets)
#if [ "$EUID" -ne 0 ]; then 
#    echo "Please run with sudo for raw socket access"
#    exit 1
#fi

# Create log directory
mkdir -p eth_logs

echo "🔌 Starting WATR Ethernet Node"
echo "   Interface: $WATR_ETH_INTERFACE"
echo "   Node Name: $WATR_ETH_NAME"
echo "   LLM Model: $WATR_ETH_LLM"
echo "   Log Level: $WATR_ETH_LOGLEVEL"

# Run the Ethernet node
sudo -E PYTHONPATH="." \
    $(which python) ethernet_llm_main.py \
    "${WATR_ETH_INTERFACE}" \
    "${WATR_ETH_NAME}" \
    "${WATR_ETH_LLM}" \
    "${WATR_ETH_LOGLEVEL}"

#source ${WATR_ROOT}/watr-header.sh

#sudo -E PYTHONPATH=".:${WATR_ROOT}/scapy" \
#	$(which python) logged_llm_social_main.py \
#	${WATR_DEVICE} ${WATR_ADDR} "${WATR_NAME}" "${WATR_LLM}"
