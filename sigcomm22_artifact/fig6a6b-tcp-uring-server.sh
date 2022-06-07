source param.sh

# Configuration
~/NetChannel/scripts/run_single_flow_set_up_tcp.sh $iface

# Run the server program
sudo taskset -c 28 ~/NetChannel/util/iouring_bench server $server_ip 9095
