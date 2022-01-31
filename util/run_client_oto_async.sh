flows=$1
proto=$2
limit=1
flow=0
while (( flow < flows ));do
	((core=20+4*flow))
	((port=6000+flow))
	taskset -c 0 ./netdriver_test_multithread 192.168.10.117:$port --limit 256 --sp $((10000+flow)) --count 1 "$proto"pingasync &
	((flow++))
	((limit=limit*4))
done
