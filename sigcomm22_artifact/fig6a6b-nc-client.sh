source param.sh

# Configuration
sudo ~/NetChannel/scripts/run_single_flow_set_up.sh $iface

# Run the client program
flows=1
protocol='nd'
flow=0
while (( flow < flows ));do
        ((core=16+4*flow))
        ((port=4000+flow))
        sudo taskset -c 28 ~/NetChannel/util/netdriver_test $server_ip:$port --sp $((6000+core)) --count 1 "$protocol"ping &
        ((flow++))
done

# Measure CPU utilization
sar -u 55 1 > cpu_util.log &

sleep 62

cpu=$(grep Average: cpu_util.log | awk '{x=$3+$5;} END {print x*32/100.0;}')
echo "CPU cores used: $cpu"
rm cpu_util.log
