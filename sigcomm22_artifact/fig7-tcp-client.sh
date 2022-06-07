source param.sh

# Configuration
~/NetChannel/scripts/run_np.sh $iface

# Run the client program
~/redis/build-client-linux
echo ""
echo "### Run redis_populate ###"
~/redis/redis_populate $server_ip 6379
echo ""

for qd in 1 2 4 8 16 32 64; do
	echo "### Queue depth = $qd ###"
	taskset -c 0-31:4 ~/redis/redis_async $server_ip 6379 8 0.75 1 $qd
	echo ""
done
