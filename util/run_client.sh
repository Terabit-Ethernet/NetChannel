server_ip=${1:-192.168.10.117}
flows=${2:-1}
protocol=${3:-nd}
flow=0
while (( flow < flows ));do
	((core=16+4*flow))
	((port=4000+flow))
	taskset -c 28 ./netdriver_test $server_ip:$port --sp $((6000+core)) --count 1 "$protocol"ping &
	((flow++))
done
