#!/bin/bash

sudo apt-get update
sudo apt-get upgrade -y
sudo apt autoremove
sudo ldconfig
exit

sudo apt-get install -y build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre2-dev libhwloc-dev libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils expect openssl libgnutls-openssl27 openvpn net-tools build-essential vim git build-essential openssh-server

git pull
git config --global user.email "bisenbek@gmail.com"
git config --global user.name "Bradley S. Isenbek"

. /home/bisenbek/.pyenv/versions/tinmac/bin/activate
python -m pip install --upgrade pip

