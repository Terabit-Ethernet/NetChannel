source param.sh

./fig8d-nc-isol-client-run.sh > thru.log &

# Measure CPU utilization
sar -u 55 1 > cpu_client.log &
ssh $server_ip 'sar -u 55 1' > cpu_server.log &

sleep 62

thru=$(grep Throughput: thru.log | awk '{x=x+$2;} END {print x;}')
cpu_client=$(grep Average: cpu_client.log | awk '{x=$3+$5;} END {print x*32/100.0;}')
cpu_server=$(grep Average: cpu_server.log | awk '{x=$3+$5;} END {print x*32/100.0;}')
cpu=$(echo $cpu_client $cpu_server | awk '{if ($1 > $2) print $1; else print $2}')
tpc=$(echo $thru $cpu | awk '{print $1/$2}')

echo "Throughput: $thru (Gbps)"
echo "CPU cores used: $cpu"
echo "Throughput-per-core: $tpc (Gbps)"
rm thru.log cpu_client.log cpu_server.log
