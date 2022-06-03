source param.sh

# Configuration
sudo ~/NetChannel/scripts/run_mix_flow_tcp.sh $iface

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

# 1 L-app
flows=1
protocol='tcp'
nice=-20
i=0
while (( i < flows ));do
	sudo nice -n $nice taskset -c 0-31:4 ~/NetChannel/util/netdriver_test $server_ip:$((6000+i%8)) --sp $((10000+i)) --count 1 "$protocol"pingpong > result_"$protocol"_pingpong_"$i"&
    (( i = 1 + i ))
done

sleep 62

python3 ~/NetChannel/util/read_pingpong.py 1 nd
rm result_nd_pingpong_0
