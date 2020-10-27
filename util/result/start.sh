# This script starts up the Homa module and configures it for the
# local system. If Homa was previously installed, it is uninstalled.
# Usage:
# start_xl170 [mod_file]

if [ $# -eq 1 ]; then
    homa=$1
else
    homa=/lib/modules/5.4.0-rc3/extra/homa.ko
fi
# vlan=vlan287

# sudo ip link set ens1f1 mtu 1500
# sudo ip link set $vlan mtu 1500
sudo rmmod homa
sudo insmod $homa
sudo sysctl /net/homa/link_mbps=100000
sudo sysctl /net/homa/max_nic_queue_ns=10000
sudo sysctl /net/homa/rtt_bytes=70000
sudo sysctl /net/homa/grant_increment=10000
sudo sysctl /net/homa/max_gso_size=20000
sudo sysctl /net/homa/num_priorities=1
# sudo sysctl /net/homa/verbose=1
# sudo cpupower frequency-set -g performance
# sudo ethtool -C ens1f1 adaptive-rx off rx-usecs 0 rx-frames 1

# Clean metrics for metrics.py
# rm -f ~/.homa_metrics

# Turn on RPS and RFS
# sudo sysctl -w net.core.rps_sock_flow_entries=32768
# for f in /sys/class/net/ens1f1/queues/rx-*/rps_flow_cnt; do
#     sudo bash -c "echo 2048 > $f"
#     done
# for f in /sys/class/net/ens1f1/queues/rx-*/rps_cpus; do
#     sudo bash -c "echo fffff > $f"
#     done
# sudo ethtool -K ens1f1 ntuple on
sudo ./enable_arfs.sh enp37s0f1
# Set VLAN priority mappings
# sudo vconfig set_egress_map $vlan 1 1
# sudo vconfig set_egress_map $vlan 2 0
# sudo vconfig set_egress_map $vlan 3 2
# sudo vconfig set_egress_map $vlan 4 3
# sudo vconfig set_egress_map $vlan 5 4
# sudo vconfig set_egress_map $vlan 6 5
# sudo vconfig set_egress_map $vlan 7 6
# sudo vconfig set_egress_map $vlan 8 7