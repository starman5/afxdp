# !/bin/bash

cd net; make clean && make -j
cd ../advanced03-AF_XDP; make clean && make -j
cd ..

all_followers=("192.168.6.2" "192.168.6.3" "192.168.6.4" "192.168.6.5")
for fip in "${all_followers[@]}"; do
  rsync -auv -e 'ssh -o StrictHostKeyChecking=no' ~/afxdp/ $fip:~/afxdp/ &
done

wait

# sudo ./af_xdp_user -d ens1f1np1 -z
# The -z flag forces zero-copy mode.  Without it, it will probably default to copy mode
# -p means using polling with timeout of 1ms.

# For client machines
# Start followers first. Run this on each follower client machine: ./follower [num threads] [follower ip]
# Then start leader: ./leader [num_followers] [num leader threads] [follower ip 1] [follower ip 2] ... [follower ip n]


sudo systemctl stop irqbalance

(let CPU=0; cd /sys/class/net/ens1f1np1/device/msi_irqs/;
  for IRQ in *; do
    echo $CPU | sudo tee /proc/irq/$IRQ/smp_affinity_list
    # let CPU=$(((CPU+1)%ncpu))
done)

# ./leader 3 40 192.168.6.3 192.168.6.4 192.168.6.5
# ./follower 40 192.168.6.3
# ./follower 40 192.168.6.4
# ./follower 40 192.168.6.5