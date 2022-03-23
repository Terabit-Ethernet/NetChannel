flows=$1
#core_id=12
i=0
nice=$2
while (( i < flows ));do
	nice -n $nice taskset -c 0-31:4 ./pingpong_server --ip 192.168.10.117 --port $((6000 + i)) & 
        (( i = i + 1))
done
