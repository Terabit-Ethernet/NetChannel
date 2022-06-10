source param.sh

# Configuration
~/NetChannel/scripts/run_single_flow_set_up_tcp.sh $iface

# Run the client program
sudo taskset -c 28 ~/NetChannel/util/iouring_bench client $server_ip 9095 60 &

# Measure CPU utilization
ssh -t $account@$server_ip 'sar -u 55 1 -P 4,28' > cpu_server.log &
ssh -t $account@$server_ip 'sudo /usr/src/linux-5.4.43/tools/perf/perf record -F 99 -a -- sleep 55'

sleep 7

ssh -t $account@$server_ip 'sudo /usr/src/linux-5.4.43/tools/perf/perf report > perf.log'
ssh -t $account@$server_ip 'cat perf.log' > perf.log
ssh -t $account@$server_ip 'sudo rm perf.data perf.log'

thru=$(grep Throughput: thru.log | awk '{x=x+$2;} END {print x;}')
grep 'Average:          4' cpu_server.log > cpu_server2.log
grep 'Average:         28' cpu_server.log >> cpu_server2.log
cpu_server=$(grep Average: cpu_server.log | awk '{x=x+$3+$5;} END {print x/100.0;}')

echo ""
echo "Throughput: $thru (Gbps)"
echo ""
echo "Receiver-side CPU breakdown (#cores):"
python3 ~/NetChannel/scripts/cpu_breakdown_fig2.py perf.log $cpu_server
cat perf.log_result
rm perf.log perf.log_result thru.log cpu_server.log cpu_server2.log
