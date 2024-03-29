source param.sh

# Configuration
~/NetChannel/scripts/run_single_flow_set_up_tcp.sh $iface

# Run the client program
sudo taskset -c 28 ~/NetChannel/util/iouring_bench client $server_ip 9095 60 > thru.log &

# [Note] we are measuring the utilization of NUMA0 cores:
ssh -t $server_ip 'sar -u 55 1 -P 0,4,8,12,16,20,24,28' > cpu_server.log &
ssh -t $server_ip 'sudo /usr/src/linux-5.4.43/tools/perf/perf record -F 99 -a -- sleep 55'

sleep 7

ssh -t $server_ip 'sudo /usr/src/linux-5.4.43/tools/perf/perf report > perf.log'
ssh -t $server_ip 'cat perf.log' > perf.log
ssh -t $server_ip 'sudo rm perf.data perf.log'

thru=$(grep Throughput: thru.log | awk '{x=x+$2;} END {print x;}')
grep 'Average:          0' cpu_server.log > cpu_server2.log
grep 'Average:          4' cpu_server.log >> cpu_server2.log
grep 'Average:          8' cpu_server.log >> cpu_server2.log
grep 'Average:         12' cpu_server.log >> cpu_server2.log
grep 'Average:         16' cpu_server.log >> cpu_server2.log
grep 'Average:         20' cpu_server.log >> cpu_server2.log
grep 'Average:         24' cpu_server.log >> cpu_server2.log
grep 'Average:         28' cpu_server.log >> cpu_server2.log
cpu_server=$(grep Average: cpu_server2.log | awk '{x=x+$3+$5;} END {print x/100.0;}')

echo ""
echo "Throughput: $thru (Gbps)"
echo ""
echo "Receiver-side CPU breakdown (#cores):"
python3 ~/NetChannel/scripts/cpu_breakdown_fig2.py perf.log $cpu_server
cat perf.log_result
rm perf.log perf.log_result thru.log cpu_server.log cpu_server2.log
