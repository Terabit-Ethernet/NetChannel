sudo sysctl  net.nd.nd_default_sche_policy=1
sudo sysctl  net.nd.num_thpt_channels=4
sudo sysctl  net.nd.nd_num_dc_thread=0
sudo sysctl  net.nd.wmem_default=589600
sudo sysctl  net.nd.rmem_default=689600
# change back to default
sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 1291456'
sudo ethtool -K ens2f0 tso on gso on gro on lro off
sudo ifconfig ens2f0 mtu 9000
