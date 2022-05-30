flows=$1
#core_id=12
flow=0
while (( flow < flows ));do
        ((core=flow%4*4+16))
        taskset -c 0 ./server --ip 192.168.10.117 --port $((6000 + flow)) &
        (( flow++ ))
done
