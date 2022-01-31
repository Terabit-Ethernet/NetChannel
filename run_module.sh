#sudo sysctl -w net.core.rmem_max=8388608
#sudo sysctl -w net.core.wmem_max=8388608
#sudo sysctl -w net.ipv4.tcp_mem='20000000 20000000 20000000' 
#sudo sysctl -w net.ipv4.tcp_rmem='4096 87380 20000000'
#sudo sysctl -w net.ipv4.tcp_wmem='4096 65536 20000000'
sudo ethtool -G ens2f0 rx 1024
#sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 6000000'
echo 0 | sudo tee /proc/sys/kernel/sched_autogroup_enabled
sudo ethtool -L ens2f0 combined 32
sudo sysctl -w net.core.default_qdisc=pfifo_fast
sudo tc qdisc add dev ens2f0 root mq

sudo ./enable_arfs.sh ens2f0

sudo sysctl /net/nd/nd_add_host=1
sudo ethtool -K ens2f0 tso on gso on gro on lro off
sudo ifconfig ens2f0 mtu 9000
#sudo sysctl /net/nd/nd_num_queue=2
#sudo sysctl /net/nd/nd_num_dc_thread=1

# disable abishek virtual env
#sudo virsh net-autostart --disable default
#sudo systemctl stop docker.service
#sudo systemctl stop docker.socket
#sudo iptables -F
#sudo iptables -X
#sudo iptables -t nat -F
#sudo iptables -t nat -X
#sudo iptables -t mangle -F
#sudo iptables -t mangle -X
#sudo iptables -P INPUT ACCEPT
#sudo iptables -P OUTPUT ACCEPT
#sudo rmmod iptable_filter
#sudo rmmod iptable_nat
#sudo rmmod iptable_mangle
#sudo rmmod ip_tables
