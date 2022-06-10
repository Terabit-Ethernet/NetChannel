source param.sh

# Configuration
~/NetChannel/scripts/run_np_tcp.sh $iface

# Run the client program
sudo taskset -c 0 ~/NetChannel/util/iouring_bench client-shortflows $server_ip 9095 60 &

sudo /usr/src/linux-5.4.43/tools/perf/perf record -F 99 -C 0 -- sleep 55

sleep 7

sudo /usr/src/linux-5.4.43/tools/perf/perf report > perf.log
echo ""
echo "Sender-side CPU breakdown (%):"
python3 ~/NetChannel/scripts/cpu_breakdown_fig3.py perf.log
cat perf.log_result
sudo rm perf.data perf.log perf.log_result
