flows=$1
protocol=$2
i=0
cores=16
k=0
while (( i < cores ));do
    j=0
    while ((j < flows));do
	taskset -c 0 ./netdriver_test 192.168.10.117:$((4000+i)) --sp $((1000+i+j)) --count 1 "$protocol"pingpong > result_"$protocol"_pingpong_"$k"&
        ((j = 1 + j))
	((k = k + 1))
    done
    (( i = 4 + i ))
done
