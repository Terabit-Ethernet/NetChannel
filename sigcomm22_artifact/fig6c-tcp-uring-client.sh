source param.sh

# Configuration
sudo ~/NetChannel/scripts/run_np_tcp.sh $iface $1

# Run the client program
sudo taskset -c 0 ~/NetChannel/util/iouring_bench client-shortflows $server_ip 9095 60
