# !/bin/bash

git submodule update --init
sudo apt install clang-11 llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic -y
sudo mv /usr/bin/clang-11 /usr/bin/clang
sudo apt install linux-headers-$(uname -r)

./configure
cd lib/xdp-tools && ./configure && make -j
cd .. && make -j
cd .. && Make -j
cd advanced03-AF_XDP && make -j

sudo ethtool -N ens1f1 rx-flow-hash udp4 fn
sudo ethtool -N ens1f1 flow-type udp4 action 20
# In order to use zero-copy mode, must be queue id 10-20
# Using `sudo ethtool -n ens1f1` to check existing rules
# Using `sudo ethtool -N ens1f1 delete 1022` to delete any redundant rules, which impacts ens1f1 receiving packets in AF_XDP.

# sudo arp -s [ip addr] [ethernet addr]

# sudo ./af_xdp_user -d ens1f1 -z
# The -z flag forces zero-copy mode.  Without it, it will probably default to copy mode

# For client machines
# Start followers first. Run this on each follower client machine: ./follower [num threads] [follower ip]
# Then start leader: ./leader [num_followers] [num leader threads] [follower ip 1] [follower ip 2] ... [follower ip n]
