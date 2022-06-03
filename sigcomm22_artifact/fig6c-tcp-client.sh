source param.sh

# Configuration
sudo ~/NetChannel/scripts/run_np_tcp.sh $iface $1

# Run the client program
flows=1
protocol='tcp'
nice=-20
i=0
while (( i < flows ));do
	sudo nice -n $nice taskset -c 0 ~/NetChannel/util/netdriver_test_multithread $server_ip:$((6000+i%8)) --sp $((10000+i)) --count 1 "$protocol"ppasync
    (( i = 1 + i ))
done
