server_ip=${1:-192.168.10.117}
flows=${2:-1}
#core_id=12
flow=0
while (( flow < flows ));do
        ((core=flow%4*4+16))
        taskset -c 28 ./server --ip $server_ip --port $((4000 + flow)) &
        (( flow++ ))
done
