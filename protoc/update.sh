#!/bin/bash
sudo apt-get update
sudo apt-get upgrade -y
sudo apt autoremove
python -m pip install --upgrade pip
sudo apt-get install libssl-dev
sudo apt-get install openssl
sudo apt-get install libtool
python -m pip uninstall scapy

