flows=$1
proto=$2
flow=0
while (( flow < flows ));do
	((core=flow))
	((port=4000+flow))
	taskset -c $(((flow * 4) % 32)) ./netdriver_test 192.168.10.117:$port --sp $((10000+core)) --count 1 "$proto"ping &
	((flow++))
done
