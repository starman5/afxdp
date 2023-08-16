# !/bin/bash

sudo ethtool -N ens1f1np1 rx-flow-hash udp4 fn
sudo ethtool -N ens1f1np1 flow-type udp4 action 20
# In order to use zero-copy mode, must be queue id 20-39
# Using `sudo ethtool -n ens1f1np1` to check existing rules
# Using `sudo ethtool -N ens1f1np1 delete 1022` to delete any redundant rules, which impacts ens1f1np1 receiving packets in AF_XDP.

sudo systemctl stop irqbalance

(let CPU=0; cd /sys/class/net/ens1f1np1/device/msi_irqs/;
  for IRQ in *; do
    echo $CPU | sudo tee /proc/irq/$IRQ/smp_affinity_list
done)
