# net-driver_impl

Assuming we have two servers,
1. Change the IP address inside the nd_plumbing.c file. data_cpy_core refers to the first core for doing the data copy. In this case, core 12 will be the first core  doing the data copy. num_nd_queues specifies the total number of ND conns.
   ```
    params->local_ip = "192.168.10.116";
    params->remote_ip = "192.168.10.117";
    params->data_cpy_core = 12;
    params->num_nd_queues = 8;
   ```
2. Compile and Load net-driver kernel module:
 
   ```
   make
   sudo insmod nd_module.ko
   ```
3. Initiate the number of ND Conns and data copy cores for being used.
   ```
   sudo ./run_module.sh
   ```
4. Compile sample apps from /util; Make sure you change the host IP adddress inside the netdriver_test.cc
   ```
   cd util
   make
   ```
5. In the server side, 
   ```
   taskset -c $CORE ./server --ip 192.168.10.117 --port 4000
   ```
6. In the client side,
  ```
  sudo -s
  taskset -c 28 ./netdriver_test 192.168.10.117:4000 --sp 1000 --count 10  ndping
  ```
7. You can tune the number of ND connections and the data copy cores:
 ```
 sudo sysctl /net/nd/nd_num_queue=1
 sudo sysctl /net/nd/nd_num_dc_thread=1
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
    ./run_client.sh 1
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
 
