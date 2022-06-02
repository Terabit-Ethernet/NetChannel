source param.sh

# Configuration
sudo ~/NetChannel/scripts/run_single_flow_set_up.sh $iface
sudo sysctl  net.nd.nd_num_dc_thread=0

# Run the client program
sudo taskset -c 28 ~/NetChannel/util/iouring_bench_nc client $server_ip 9095 60 &

# Measure CPU utilization
sar -u 55 1 > cpu_client.log &
ssh $server_ip 'sar -u 55 1' > cpu_server.log &

sleep 62

cpu_client=$(grep Average: cpu_client.log | awk '{x=$3+$5;} END {print x*32/100.0;}')
cpu_server=$(grep Average: cpu_server.log | awk '{x=$3+$5;} END {print x*32/100.0;}')
cpu=$(echo $cpu_client $cpu_server | awk '{if ($1 > $2) print $1; else print $2}')

echo "CPU cores used: $cpu"
rm cpu_client.log cpu_server.log
