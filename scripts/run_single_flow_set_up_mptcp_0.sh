iface=${1:-ens2f0}
sudo ethtool -G $iface rx 1024
sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 6291456'
sudo ethtool -K $iface tso on gso on gro on lro off
sudo ifconfig $iface mtu 9000
