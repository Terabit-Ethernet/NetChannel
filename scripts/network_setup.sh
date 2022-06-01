#!/bin/bash
device_ip=${1:-192.168.10.116}
iface=${2:-ens2f0}
sudo ip link set arp off dev $iface ; ip link set arp on dev $iface
sudo ethtool -G $iface rx 1024
#sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 6000000'
echo 0 | sudo tee /proc/sys/kernel/sched_autogroup_enabled
sudo ethtool -L $iface combined 32
sudo sysctl -w net.core.default_qdisc=pfifo_fast
sudo tc qdisc add dev $iface root mq

sudo ./enable_arfs.sh $iface

sudo ethtool -K $iface tso on gso on gro on lro off
sudo ifconfig $iface $device_ip mtu 9000
