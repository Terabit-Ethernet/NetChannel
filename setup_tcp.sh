# change back to default
sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 6291456'
sudo ethtool -K ens2f0 tso on gso on gro on lro off
sudo ifconfig ens2f0 mtu 9000
