source param.sh

# Configuration
sudo ~/NetChannel/scripts/run_np.sh $iface $1

# Run the server program
sudo taskset -c 28 ~/NetChannel/util/iouring_bench_nc client-shortflows-qd $server_ip 9095 60
