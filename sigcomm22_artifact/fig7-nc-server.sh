source param.sh

# Configuration
sudo ~/NetChannel/scripts/run_np.sh $iface

# Run the server program
sudo taskset -c 0 ~/redis/src/redis-server ~/redis/redis_nd.conf
