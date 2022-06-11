source param.sh

# Configuration
~/NetChannel/scripts/run_single_flow_set_up_tcp.sh $iface

# Run the client program
flows=1
protocol='tcp'
flow=0
while (( flow < flows ));do
        ((core=16+4*flow))
        ((port=4000+flow))
	sudo taskset -c 28 ~/NetChannel/util/netdriver_test $server_ip:$port --sp $((6000+core)) --count 1 "$protocol"ping > thru.log &
        #sudo taskset -c 28 iperf -c $server_ip -p $port -t 60 &
        ((flow++))
done

# Measure CPU utilization
ssh -t $server_ip 'sar -u 55 1 -P 4,28' > cpu_server.log &
ssh -t $server_ip 'sudo /usr/src/linux-5.4.43/tools/perf/perf record -F 99 -a -- sleep 55'

sleep 7

ssh -t $server_ip 'sudo /usr/src/linux-5.4.43/tools/perf/perf report > perf.log'
ssh -t $server_ip 'cat perf.log' > perf.log
ssh -t $server_ip 'sudo rm perf.data perf.log'

thru=$(grep Throughput: thru.log | awk '{x=x+$2;} END {print x;}')
grep 'Average:          4' cpu_server.log > cpu_server2.log
grep 'Average:         28' cpu_server.log >> cpu_server2.log
cpu_server=$(grep Average: cpu_server2.log | awk '{x=x+$3+$5;} END {print x/100.0;}')

echo ""
echo "Throughput: $thru (Gbps)"
echo ""
echo "Receiver-side CPU breakdown (#cores):"
python3 ~/NetChannel/scripts/cpu_breakdown_fig2.py perf.log $cpu_server
cat perf.log_result
rm perf.log perf.log_result thru.log cpu_server.log cpu_server2.log
