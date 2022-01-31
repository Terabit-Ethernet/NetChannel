flows=$1
protocol=$2
nice=$3
i=0
while (( i < flows ));do
	nice -n $nice taskset -c 0 ./netdriver_test_multithread 192.168.10.117:$((6000+i%8)) --sp $((10000+i)) --count 1 "$protocol"ppasync 
	#> result_"$protocol"_pingpongasync_"$i"&
    (( i = 1 + i ))
done
