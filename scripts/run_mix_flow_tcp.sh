iface=${1:-ens2f0}
sudo sysctl  net.nd.nd_default_sche_policy=1
sudo sysctl  net.nd.num_thpt_channels=4
sudo sysctl  net.nd.nd_num_dc_thread=0
sudo sysctl  net.nd.wmem_default=589600
sudo sysctl  net.nd.rmem_default=689600
# change back to default
sudo ethtool -G $iface rx 1024
sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 6291456'
sudo ethtool -K $iface tso on gso on gro on lro off
sudo ifconfig $iface mtu 9000
