flows=$1
#core_id=12
i=0
while (( i < flows ));do
	taskset -c 0 ./pingpong_server --ip 192.168.10.117 --port $((4000 + i)) & 
        (( i++ ))
done
