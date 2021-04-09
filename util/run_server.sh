flows=$1
#core_id=12
flow=0
while (( flow < flows ));do
	((core=16+4*flow))
	taskset -c $core ./server --ip 192.168.10.117 --port $((4000 + flow)) > result_nd_$flow & 
        (( flow++ ))
done
