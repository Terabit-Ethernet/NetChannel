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
        sudo taskset -c 28 ~/NetChannel/util/netdriver_test $server_ip:$port --sp $((6000+core)) --count 1 "$protocol"ping &
        ((flow++))
done

# Measure CPU utilization
sar -u 55 1 > cpu_client.log &
ssh $server_ip 'sar -u 55 1' > cpu_server.log &

sleep 62

cpu_client=$(grep Average: cpu_client.log | awk '{x=$3+$5;} END {print x*32/100.0;}')
cpu_server=$(grep Average: cpu_server.log | awk '{x=$3+$5;} END {print x*32/100.0;}')
cpu=$(echo $cpu_client $cpu_server | awk '{if ($1 > $2) print $1; else print $2}')

echo "CPU cores used: $cpu"
rm cpu_client.log cpu_server.log
