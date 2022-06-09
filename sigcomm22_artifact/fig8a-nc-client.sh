source param.sh

# Configuration
~/NetChannel/scripts/run_single_flow_set_up_0.sh $iface

# Run the client program
flows=1
protocol='nd'
flow=0
while (( flow < flows ));do
        ((core=16+4*flow))
        ((port=4000+flow))
        sudo taskset -c 16 ~/NetChannel/util/netdriver_test $server_ip:$port --sp $((6000+core)) --count 1 "$protocol"ping > thru.log &
        ((flow++))
done

# Measure CPU utilization
sar -u 55 1 -P 16 > cpu_client.log &
ssh $server_ip 'sar -u 55 1 -P 16' > cpu_server.log &

sleep 62

thru=$(grep Throughput: thru.log | awk '{print $2;}');
cpu_client=$(grep Average: cpu_client.log | awk '{x=$3+$5;} END {print x/100.0;}')
cpu_server=$(grep Average: cpu_server.log | awk '{x=$3+$5;} END {print x/100.0;}')
cpu=$(echo $cpu_client $cpu_server | awk '{if ($1 > $2) print $1; else print $2}')
tpc=$(echo $thru $cpu | awk '{print $1/$2}')

echo "Throughput: $thru (Gbps)"
echo "CPU cores used: $cpu"
echo "Throughput-per-core: $tpc (Gbps)"
rm thru.log cpu_client.log cpu_server.log
