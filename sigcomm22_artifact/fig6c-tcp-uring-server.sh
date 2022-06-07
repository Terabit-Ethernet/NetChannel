source param.sh

# Configuration
~/NetChannel/scripts/run_np_tcp.sh $iface

# Run the server program
sudo taskset -c 0 ~/NetChannel/util/iouring_bench server $server_ip 9095
