#!/bin/sh

intf=${1:-ens2f0}

ethtool -K $intf ntuple on

if [ $? -gt 0 ]; then

echo "ERROR to enble ntuple"

# exit

fi

echo 32768 > /proc/sys/net/core/rps_sock_flow_entries

for f in /sys/class/net/$intf/queues/rx-*/rps_flow_cnt; do echo 32768 > $f; done

/usr/sbin/set_irq_affinity.sh $intf
service irqbalance stop
