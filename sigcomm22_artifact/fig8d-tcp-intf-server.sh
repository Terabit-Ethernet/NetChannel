source param.sh

# Configuration
~/NetChannel/scripts/run_mix_flow_tcp.sh $iface

# Run the server program

# 1 L-app
flows=1
i=0
nice=-20
while (( i < flows ));do
        sudo nice -n $nice taskset -c 0-31:4 ~/NetChannel/util/pingpong_server --ip $server_ip --port $((6000 + i)) &
        (( i = i + 1))
done

# 8 T-apps
flows=8
flow=0
while (( flow < flows ));do
	((core=flow%4*4+16))
	sudo taskset -c 0-31:4  ~/NetChannel/util/server --ip $server_ip --port $((4000 + flow)) &
	(( flow++ ))
done
