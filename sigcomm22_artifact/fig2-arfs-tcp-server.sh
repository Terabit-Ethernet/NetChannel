source param.sh

# Configuration
~/NetChannel/scripts/run_single_flow_set_up_tcp_0.sh $iface

# Run the server program
flows=1
#core_id=12
flow=0
while (( flow < flows ));do
        ((core=flow%4*4+16))
        sudo taskset -c 28 ~/NetChannel/util/server --ip $server_ip --port $((4000 + flow)) &
        (( flow++ ))
done
