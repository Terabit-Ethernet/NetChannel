flows=$1
proto=$2
flow=0
while (( flow < flows ));do
	((core=20+4*flow))
	((port=4000+flow))
	taskset -c 0-13:4 ./netdriver_test_multithread 192.168.10.117:$port --sp $((10000+core)) --count 4 "$proto"ping &
	((flow++))
done
