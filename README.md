# NetChannel: Disaggregating the Host Network Stack

## 1. Overview

### Repository overview

### System overview

### Getting Started Guide

## 2. Build Kernel (with root)

## 3. Build NetChannel Module

1. Change the local IP, remote IP address and the number of remote hosts inside the nd_plumbing.c file (line 281).

    ```
    params->local_ip = "192.168.10.117";

    /* set the number of remote hosts */
    params->num_remote_hosts = 2;
    params->remote_ips[0] = "192.168.10.116";
    params->remote_ips[1] = "192.168.10.117";
   ```
   
   And in `run_module.sh`, change the  IP address,
   
2. Compile and load net-driver kernel module:
 
   ```
   make
   sudo insmod nd_module.ko
   ```
   
   Configure your NIC:
   
   ```
   sudo ./network_setup.sh $IP $IFACE_NAME
   ```
   
3. **After load kernel modeuls in all machines**, initiate connections:.
   ```
   sudo ./run_module.sh
   ```
4. Compile sample apps from /util; Make sure you change the host IP adddress inside the netdriver_test.cc
   ```
   cd util
   make
   cd ../
   ```
 
 ## SIGCOMM 2022 Artifact Evaluation
 
 1. Figure 6a, 6b (data copy processing parallelism experiment),
 
    For the normal read/write syscall experiment,

    On the server side:

    ```
    sudo ./run_single_flow_set_up.sh 
    cd util/
    ./run_single_server.sh 1
    ```

    On the client side:

    ```
    sudo ./run_single_flow_set_up.sh 
    cd util/
    ./run_client.sh 1 nd
    ```
    The throughput will be shown on the server side. After the experiment finishes, kill the server: `sudo killall server`.
 
 2. Figure 6c (network processing parallelism experiment),
 
    For the normal read/write syscall experiment,

    On the server side:

    ```
    sudo ./run_np.sh 
    cd util/
    ./run_np_server.sh 1
    ```

    On the client side:

    ```
    sudo ./run_np.sh 
    cd util/
    ./run_pingpong_setup3.sh 1 nd
    ```
    The throughput will be shown on the server side. After the experiment finishes, kill the server: `sudo killall server`.
The `run_np.sh` will set the number of throught channel to be 4. To change the number of thpt channel to be 1 : `sudo sysctl  net.nd.num_thpt_channels=1` on both sides and rerun the experiments again for getting new results.

3. Figure 6d (performance isolation experiment),

    On the server side:

    ```
    sudo ./run_mix_flow.sh 
    cd util/
    sudo -s
    ./run_pingpong.sh 1 -20
    ./run_server.sh 8
    ```

    On the client side:

    ```
    sudo ./run_mix_flow.sh
    cd util/
    sudo -s
    ./run_client_oto.sh 8 nd
    ./run_pingpong_setup1.sh 1 nd -20
    ```
### TCP setup
    
 1. Figure 6a, 6b (data copy processing parallelism experiment),
 
    For the normal read/write syscall experiment,

    On the server side:

    ```
    sudo ./run_single_flow_set_up_tcp.sh 
    cd util/
    ./run_single_server.sh 1
    ```

    On the client side:

    ```
    sudo ./run_single_flow_set_up_tcp.sh 
    cd util/
    ./run_client.sh 1 tcp
    ```
    The throughput will be shown on the server side. After the experiment finishes, kill the server: `sudo killall server`.
 
 2. Figure 6c (network processing parallelism experiment),
 
    For the normal read/write syscall experiment,

    On the server side:

    ```
    sudo ./run_np_tcp.sh 
    cd util/
    ./run_np_server.sh 1
    ```

    On the client side:

    ```
    sudo ./run_np_tcp.sh 
    cd util/
    ./run_pingpong_setup3.sh 1 tcp
    ```
    The throughput will be shown on the server side. After the experiment finishes, kill the server: `sudo killall server`.
The `run_np.sh` will set the number of throught channel to be 4. To change the number of thpt channel to be 1 : `sudo sysctl  net.nd.num_thpt_channels=1` on both sides and rerun the experiments again for getting new results.

3. Figure 6d (performance isolation experiment),

    On the server side:

    ```
    sudo ./run_mix_flow_tcp.sh 
    cd util/
    sudo -s
    ./run_pingpong.sh 1 -20
    ./run_server.sh 8
    ```

    On the client side:

    ```
    sudo ./run_mix_flow_tcp.sh
    cd util/
    sudo -s
    ./run_client_oto.sh 8 tcp
    ./run_pingpong_setup1.sh 1 tcp -20
    ```
    
### io_uring bench setup

 1. Clone liburing and build

 ```
 git clone https://github.com/axboe/liburing
 cd liburing
 make
 cd ..
 ```
 For artifact evaluation, we have installed the liburing for you, you can jump into the step 3.

 2. Set liburing-path in Makefile in this directory
 
 Example:

 ```
 liburing-path = /home/midhul/liburing
 ```

 3. build iouring_bench
 ```
 make iouring_bench iouring_bench_nc
 ```

 4. Figure 6a (data copy processing parallelism)

 On the server side,
 
 ```
 sudo ./run_single_flow_set_up.sh 
 cd util/
 sudo taskset -c 28 ./iouring_bench_nc server 192.168.10.117 9095
 ```
 
 On the client side,
 
 ```
 sudo ./run_single_flow_set_up.sh 
 sudo sysctl  net.nd.nd_num_dc_thread=0
 cd util/
 sudo taskset -c 28 ./iouring_bench_nc server 192.168.10.117 9095
 ```

 5. Figure 6b (network processing parallelism) 

 On the server side,
 
 ```
 sudo ./run_np.sh 
 cd util/
 sudo taskset -c 28 ./iouring_bench_nc server 192.168.10.117 9095
 ``` 
 
 On the client side,
 
 ```
 sudo ./run_np.sh 
 cd util/
 sudo taskset -c 28 ./iouring_bench_nc client-shortflows-qd 192.168.10.117 9095 180
 ```
### Redis Experiment
 
 1. Clone the repo of Redis and build Redis at both sides,
 
 ```
 git clone https://github.com/qizhe/redis.git
 cd redis/
 make
 sudo ~/NetChannel/run_np.sh
 ```
 
 2. On the server side,
 
 ```
 sudo taskset -c 0 ./src/redis-server redis_nd.conf 
 ```
 
 3. On the client side,
 
 Compile the client code first

```
 cd redis/deps/hiredis
 make 
 sudo make install
 cd ../../
 g++ redis_async.cpp -lpthread -lhiredis -o redis_async
 g++ redis_populate.cpp -levent -lpthread -lhiredis -o redis_populate
 ```
 
 We need to populate the database first,
 
 ```
 ./redis_populate
 ```
 
 Then running the experiment,
 
 ```
 taskset -c 0-31:4 ./redis_async 192.168.10.117 6379 8 0.75 1 1
 ```
 
 The client uses 8 threads and each thread queue depth is 1. To tune the queue depth,
 
 ```
 taskset -c 0-31:4 ./redis_async 192.168.10.117 6379 8 0.75 1 $QUEUE_DEPTH$
 ```
 
