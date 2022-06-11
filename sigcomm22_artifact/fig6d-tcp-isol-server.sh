source param.sh

# Configuration
~/NetChannel/scripts/run_mix_flow_tcp.sh $iface

# Run the server program

# 1 L-app
flows=1
i=0
nice=-20
while (( i < flows ));do
        sudo nice -n $nice taskset -c 0 ~/NetChannel/util/pingpong_server --ip $server_ip --port $((6000 + i)) &
        (( i = i + 1))
done
