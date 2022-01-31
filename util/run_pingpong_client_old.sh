flows=$1
protocol=$2
i=0
while (( i < flows ));do
	taskset -c 0 ./netdriver_test 192.168.10.117:$((4000+i)) --sp $((1000+i)) --count 1 "$protocol"pingpong > result_"$protocol"_pingpong_"$i"&
    (( i = 1 + i ))
done
