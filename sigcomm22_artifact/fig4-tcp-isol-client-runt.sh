source param.sh

# Configuration
~/NetChannel/scripts/run_mix_flow_tcp.sh $iface

# Run the client program

# 8 T-apps
flows=8
protocol='tcp'
flow=0
while (( flow < flows ));do
	((core=flow))
	((port=4000+flow))
	sudo taskset -c 0-31:4 ~/NetChannel/util/netdriver_test $server_ip:$port --sp $((10000+core)) --count 1 "$protocol"ping &
	((flow++))
done
