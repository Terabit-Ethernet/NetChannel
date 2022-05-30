sudo sysctl  net.nd.nd_default_sche_policy=0
sudo sysctl  net.nd.num_thpt_channels=2
sudo sysctl  net.nd.nd_num_dc_thread=2
sudo sysctl  net.nd.wmem_default=6289600
sudo sysctl  net.nd.rmem_default=6289600
# change back to default
sudo sysctl -w net.ipv4.tcp_rmem='4096 131072 6000000'
