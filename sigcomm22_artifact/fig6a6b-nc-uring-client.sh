source param.sh

# Configuration
sudo ~/NetChannel/scripts/run_single_flow_set_up.sh $iface
sudo sysctl  net.nd.nd_num_dc_thread=0

# Run the client program
sudo taskset -c 28 ~/NetChannel/util/iouring_bench_nc client $server_ip 9095 60 &

# Measure CPU utilization
sar -u 55 1 > cpu_util.log &

sleep 62

cpu=$(grep Average: cpu_util.log | awk '{x=$3+$5;} END {print x*32/100.0;}')
echo "CPU cores used: $cpu"
rm cpu_util.log
