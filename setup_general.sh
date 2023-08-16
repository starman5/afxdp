# !/bin/bash

git submodule update --init
sudo apt-get update
sudo apt install clang-11 llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic m4 -y
sudo mv /usr/bin/clang-11 /usr/bin/clang
sudo apt install linux-headers-$(uname -r)

./configure
cd lib/xdp-tools && ./configure && make -j
cd .. && make -j
cd .. && Make -j
cd advanced03-AF_XDP && make -j

# sudo arp -s [ip addr] [ethernet addr]
