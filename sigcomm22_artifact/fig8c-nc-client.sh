source param.sh

# Configuration
sudo ~/NetChannel/scripts/run_np.sh $iface $1

# Run the client program
flows=1
protocol='nd'
nice=-20
i=0
while (( i < flows ));do
	sudo nice -n $nice taskset -c 0 ~/NetChannel/util/netdriver_test_multithread $server_ip:$((6000+i%8)) --sp $((10000+i)) --count 1 "$protocol"ppasync > thru.log &
    (( i = 1 + i ))
done

# Measure CPU utilization
sar -u 55 1 > cpu_client.log &
ssh $server_ip 'sar -u 55 1' > cpu_server.log &

sleep 62

thru=$(grep Throughput: thru.log | awk '{print $2;}');
cpu_client=$(grep Average: cpu_client.log | awk '{x=$3+$5;} END {print x*32/100.0;}')
cpu_server=$(grep Average: cpu_server.log | awk '{x=$3+$5;} END {print x*32/100.0;}')
cpu=$(echo $cpu_client $cpu_server | awk '{if ($1 > $2) print $1; else print $2}')
tpc=$(echo $thru $cpu | awk '{print $1/$2}')

echo "Throughput: $thru (Gbps)"
echo "CPU cores used: $cpu"
echo "Throughput-per-core: $tpc (Gbps)"
rm thru.log cpu_client.log cpu_server.log
