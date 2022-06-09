source param.sh

# Configuration
~/NetChannel/scripts/run_mix_flow_tcp.sh $iface

# Run the server program

# 8 T-apps
flows=8
flow=0
while (( flow < flows ));do
	((core=flow%4*4+16))
	sudo taskset -c 0-31:4  ~/NetChannel/util/server --ip $server_ip --port $((4000 + flow)) &
	(( flow++ ))
done
