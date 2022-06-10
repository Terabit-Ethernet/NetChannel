source param.sh

# Configuration
~/NetChannel/scripts/run_np_tcp.sh $iface

# Run the client program
flows=1
protocol='tcp'
nice=-20
i=0
while (( i < flows ));do
	sudo nice -n $nice taskset -c 0 ~/NetChannel/util/netdriver_test_multithread $server_ip:$((6000+i%8)) --sp $((10000+i)) --count 1 "$protocol"ppasync &
    (( i = 1 + i ))
done

sudo /usr/src/linux-5.4.43/tools/perf/perf record -F 99 -C 0 -- sleep 55

sleep 7

sudo /usr/src/linux-5.4.43/tools/perf/perf report > perf.log
echo ""
echo "Sender-side CPU breakdown (%):"
python3 ~/NetChannel/scripts/cpu_breakdown_fig3.py perf.log
cat perf.log_result
sudo rm perf.data perf.log perf.log_result
