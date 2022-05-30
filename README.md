# NetChannel: Disaggregating the Host Network Stack
NetChannel is a new disaggregated network stack architecture that enables resources allocated to each layer in the packet processing pipeline to be scaled and scheduled independently. Evaluation of an end-to-end realization of NetChannel within the Linux network stack demonstrates that NetChannel enables new operating points that were previously unachievable:
- Independent scaling of data copy processing allows a single application thread to saturate 100Gbps access link bandwidth.
- Independent scaling of network connections allows short flows to increase throughput almost linearly with cores.
- Dynamic scheduling of packets between application threads and network connections at fine-grained timescales allows latency-sensitive applications to achieve µs-scale tail latency, even when competing with bandwidth-intensive applications operating at near-line rate.

## 1. Overview
### Repository overview
- `kernel_patch/` includes some modifications in the kernel code.
- `module/` includes NetChannel kernel modules.
- `scripts/` includes scripts for getting started instructions.
- `sigcomm22_artifact/` includes scripts for SIGCOMM 2022 artifact evaluation.
- `util/` includes sample applications.

### System overview
For simplicity, we assume that users have two physical servers (Client and Server) connected with each other over networks using the following configuration:
- Client: `192.168.10.116` (interface: **ens2f0**)
- Server: `192.168.10.117` (interface: **ens2f0**)

### Getting Started Guide
Through the following three sections, we provide getting started instructions to install NetChannel and to run experiments.

   - **Build NetChannel (10 human-mins + 30 compute-mins + 5 reboot-mins):**  
NetChannel requires some modifications in the Linux kernel, so it requires kernel compilation and system reboot into the NetChannel kernel. This section covers how to build (1) the Linux kernel with the NetChannel patch, (2) the NetChannel kernel modules, and (3) the NetChannel test applications.
   - **Run a Toy Experiment (5-10 compute-mins):**
This section covers how to setup the servers and run experiments with the NetChannel kernel modules.
   - **SIGCOMM 2022 Artifact Evaluation (30-40 compute-mins):**  
This section provides the detailed instructions to reproduce all individual results presented in our SIGCOMM 2022 paper.


## 2. Build NetChannel
NetChannel has been successfully tested on Ubuntu 20.04 LTS with Linux kernel 5.6. Building the NetChannel kernel and kernel modules should be done on both Client and Server machines.

### Install Prerequisites
We need to install prerequisites to compile the kernel. On Ubuntu 20.04, this can be done with
   ```
   sudo apt-get install libncurses-dev gawk flex bison openssl libssl-dev dkms dwarves  \
                     libelf-dev libudev-dev libpci-dev libiberty-dev autoconf
   ```

### NetChannel Kernel
1. Download Linux kernel source tree:
   ```
   cd ~
   wget https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.6.tar.gz
   tar xzvf linux-5.6.tar.gz
   ```

2. Download and apply the NetChannel kernel patch to the kernel source:

   ```
   git clone -b new_flow_control https://github.com/Terabit-Ethernet/NetChannel.git
   cd ~/linux-5.6/
   git apply ../NetChannel/kernel_patch/netchannel-kernel.patch
   ```

3. Update kernel configuration (with root):

   ```
   sudo -s
   cp /boot/config-`uname -r` ./.config
   make olddefconfig
   scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
   ```

4. Compile and install:

   ```
   make -j32 bzImage
   make -j32 modules
   make modules_install
   make install
   ```
   The number 32 means the number of threads created for compilation. Set it to be the total number of cores of your system to reduce the compilation time. Type `lscpu | grep 'CPU(s)'` to see the total number of cores:
   
   ```
   CPU(s):                32
   On-line CPU(s) list:   0-31
   ```

5. Edit `/etc/default/grub` to boot with your new kernel by default. For example:

   ```
   GRUB_DEFAULT="1>Ubuntu, with Linux 5.6.0-netchannel"
   ```

6. Update the grub configuration and reboot into the new kernel.

   ```
   update-grub && reboot
   ```
   
7. When system is rebooted, check the kernel version, type `uname -r` in the command-line. It should be `5.6.0-netchannel`.
   
### NetChannel Kernel Modules
1. Change the local IP, remote IP address and the number of remote hosts inside the `NetChannel/module/nd_plumbing.c` (line 281):
    ```
    params->local_ip = "192.168.10.117";

    /* set the number of remote hosts */
    params->num_remote_hosts = 2;
    params->remote_ips[0] = "192.168.10.116";
    params->remote_ips[1] = "192.168.10.117";
   ```
  
2. Compile and load the NetChannel kernel module:
    ```
   cd ~/NetChannel/module/
   make
   sudo insmod nd_module.ko
   ```

### NetChannel Applications
1. Change the host IP adddress inside the `NetChannel/util/netdriver_test.cc` (line 758):
    ```
    addr_in.sin_addr.s_addr = inet_addr("192.168.10.116");
    ```

2. Compile the test apps; 
   ```
   cd ~/NetChannel/util/
   make
   ```

## 3. Run a Toy Experiment
**Please confirm that the NetChannel kernel modules are loaded in both machines.**

### Setup NetChannel
Configure the network interface and initiate the NetChannel connections:
   ```
   cd ~/NetChannel/scripts/
   sudo ./network_setup.sh $IP $IFACE_NAME
   sudo ./run_module.sh
   ```

### Run a test application
Run a test application:
   ```
   cd ~/NetChannel/util/
   ./xxxx
   ```
 
## SIGCOMM 2022 Artifact Evaluation
### Hardware/Software Configuration
We have used the follwing hardware and software configurations for running the experiments shown in the paper.

* CPU: 4-Socket Intel Xeon Gold 6234 3.3 GHz with 8 cores per socket (with hyperthreading disabled)
* RAM: 384 GB
* NIC: Mellanox ConnectX-5 Ex VPI (100 Gbps)
* OS: Ubuntu 20.04 with Linux 5.6 (patched)

#### Caveats of Our Work
Our work has been evaluated with two servers with 4-socket multi-core CPUs and 100 Gbps NICs directly connected with a DAC cable. While we generally focus on trends rather than individual data points, other combinations of end-host network stacks and hardware may exhibit different performance characteristics. All our scripts use `network_setup.sh` to configure the NIC to allow a specific benchmark to be performed. Some of these configurations may be specific to Mellanox NICs (e.g., enabling aRFS).

### Running Experiments
All experiments must be run as `sudo`. Run the scripts corresponding to each experiment on the sender and receiver respectively.

```
sudo -s
cd ~/NetChannel/sigcomm22_artifact/
```

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
 
