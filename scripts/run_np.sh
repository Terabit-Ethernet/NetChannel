sudo sysctl  net.nd.nd_default_sche_policy=0
sudo sysctl  net.nd.num_thpt_channels=4
sudo sysctl  net.nd.nd_num_dc_thread=0
sudo sysctl  net.nd.wmem_default=589600
sudo sysctl  net.nd.rmem_default=6289600
# change back to default
sudo ethtool -G ens2f0 rx 256
sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 1291456'
sudo ethtool -K ens2f0 tso off gso off gro off lro off
sudo ifconfig ens2f0 mtu 1500
