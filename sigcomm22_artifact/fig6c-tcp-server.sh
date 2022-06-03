source param.sh

# Configuration
sudo ~/NetChannel/scripts/run_np_tcp.sh $iface $1

# Run the server program
flows=1
#core_id=12
flow=0
while (( flow < flows ));do
        ((core=flow%4*4+16))
        sudo taskset -c 0 ~/NetChannel/util/server --ip $server_ip --port $((6000 + flow)) &
        (( flow++ ))
done
