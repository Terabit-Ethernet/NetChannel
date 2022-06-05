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
Through the following sections, we provide getting started instructions to install NetChannel and to run experiments.

* **Build NetChannel**
   * **NetChannel Kernel: (10 human-mins + 30 compute-mins + 5 reboot-mins):**  
NetChannel requires some modifications in the Linux kernel, so it requires kernel compilation and system reboot into the NetChannel kernel. This section covers how to build the Linux kernel with the NetChannel patch.
   * **NetChannel Kernel Module: (5 human-mins):**  
This section covers how to build the NetChannel kernel modules.
   * **NetChannel Applications: (10 human-mins):**  
This section covers how to build the NetChannel test applications.
* **Run a Toy Experiment (5-10 compute-mins):**  
This section covers how to setup the servers and run experiments with the NetChannel kernel modules.
* **SIGCOMM 2022 Artifact Evaluation (30-40 compute-mins):**  
This section provides the detailed instructions to reproduce all individual results presented in our SIGCOMM 2022 paper.


## 2. Build NetChannel
NetChannel has been successfully tested on Ubuntu 20.04 LTS with Linux kernel 5.6. Building the NetChannel kernel and kernel modules should be done on _both Client and Server machines_.

### Install Prerequisites
We need to install prerequisites to compile the kernel. On Ubuntu 20.04, this can be done with
   ```
   sudo apt-get install libncurses-dev gawk flex bison openssl libssl-dev dkms dwarves  \
                     libelf-dev libudev-dev libpci-dev libiberty-dev autoconf sysstat
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
1. Go to the kernel module directory:  

   ```
   cd ~/NetChannel/module/
   ```
   
2. Edit `nd_plumbing.c` (line 281) to change the local IP, remote IP address and the number of remote hosts:  

   ```
   params->local_ip = "192.168.10.116";

   /* set the number of remote hosts */
   params->num_remote_hosts = 2;
   params->remote_ips[0] = "192.168.10.116";
   params->remote_ips[1] = "192.168.10.117";
   ```

   **[NOTE]** Use `params->local_ip = "192.168.10.117"` on the Server-side.  
   
  
3. Compile and load the NetChannel kernel module:  

   ```
   make
   sudo insmod nd_module.ko
   ```

### NetChannel Applications  
1. Build io_uring library (liburing):  

   ```
   cd ~
   git clone https://github.com/axboe/liburing
   cd liburing
   make
   cd ~/NetChannel/util/
   ```

2. Edit `Makefile` to set the liburing-path (line 1):  

   ```
   liburing-path = /home/(account name)/liburing
   ```

3. Edit `netdriver_test.cc` to change the host IP adddress (line 758):  

   ```
   addr_in.sin_addr.s_addr = inet_addr("192.168.10.116");
   ```

   **[NOTE]** Use `inet_addr("192.168.10.117")` on the Server-side.

4. Compile the applications:  

   ```
   make
   ```

5. Add IPPROTO_VIRTUAL_SOCK in netinet/in.h:  

   We need to define **IPPROTO_VIRTUAL_SOCK** for NetChannel applications. Add the two lines in `/usr/include/netinet/in.h` (line 58):

   ```
   ...
      IPPROTO_VIRTUAL_SOCK = 19,      /* Virtual Socket.  */
   #define IPPROTO_VIRTUAL_SOCK     IPPROTO_VIRTUAL_SOCK
   ...
   ```

## 3. Run a Toy Experiment  
**[NOTE]** You should confirm that NetChannel kernel module is loaded in both machines before activating the NetChannel module.

1. On both sides:  

   Load the NetChannel kernel module and run network configuration scripts:

   ```
   sudo insmod ~/NetChannel/module/nd_module.ko
   sudo ~/NetChannel/scripts/network_setup.sh ens2f0
   sudo ~/NetChannel/scripts/enable_arfs.sh ens2f0
   ```

2. On the Server side:  

   Activate the NetChannel kernel module and run a test server application with the Server IP address (e.g., 192.168.10.117):
   ```
   sudo ~/NetChannel/scripts/run_module.sh
   cd ~/NetChannel/util/
   ./run_single_server.sh 192.168.10.117 1
   ```

3. On the Client side:  

   Activate the NetChannel kernel module and run a test client application with the Server IP address (e.g., 192.168.10.117):
   ```
   sudo ~/NetChannel/scripts/run_module.sh
   cd ~/NetChannel/util/
   ./run_client.sh 192.168.10.117 1 nd
   ```

Type `sudo killall server` on the Server machine to stop the server application.
   
 
## SIGCOMM 2022 Artifact Evaluation
### Hardware/Software Configuration
We have used the follwing hardware and software configurations for running the experiments shown in the paper.

* CPU: 4-Socket Intel Xeon Gold 6234 3.3 GHz with 8 cores per socket (with hyperthreading disabled)
* RAM: 384 GB
* NIC: Mellanox ConnectX-5 Ex VPI (100 Gbps)
* OS: Ubuntu 20.04 with Linux 5.6 (patched)

#### Caveats of Our Work
Our work has been evaluated with two servers with 4-socket multi-core CPUs and 100 Gbps NICs directly connected with a DAC cable. While we generally focus on trends rather than individual data points, other combinations of end-host network stacks and hardware may exhibit different performance characteristics. All our scripts use `network_setup.sh` to configure the NIC to allow a specific benchmark to be performed. Some of these configurations may be specific to Mellanox NICs (e.g., enabling aRFS).

### NetChannel Configurations
On both sides:

1. Load NetChannel module:  
   ```
   sudo insmod ~/NetChannel/module/nd_module.ko
   sudo ~/NetChannel/scripts/network_setup.sh ens2f0
   sudo ~/NetChannel/scripts/enable_arfs.sh ens2f0
   ```
   
   **[NOTE] Step 1 should be done on both sides before Step 2.**

2. Activate NetChannel module:  
   ```
   sudo ~/NetChannel/scripts/run_module.sh
   cd ~/NetChannel/sigcomm22_artifact/
   ```
   
3. Edit `param.sh` to change the IP addresses and interface name:
   ```
   client_ip=192.168.10.116
   server_ip=192.168.10.117
   iface=ens2f0
   ```
   
4. (**Skip if configured**) Configure `sysstat` and `ssh`:

   We use `sar/sysstat` and `ssh` to measure CPU utilization in the artifact evaluation scripts. Please refer to [Installing sar/sysstat](https://www.digitalocean.com/community/questions/how-to-install-and-configure-sar-sysstat-on-ubuntu) (both sides) and [SSH login without password](https://www.thegeekstuff.com/2008/11/3-steps-to-perform-ssh-login-without-password-using-ssh-keygen-ssh-copy-id/) (Client-side only). Once the configrations are done correctly, you should be able to measure Server-side CPU utilization via the following command:
   
   Client: `ssh 192.168.10.117 'sar -u 3 1'`
   ```
   Linux 5.6.0-netchannel (xxxx)         xx/xx/2022      _x86_64_        (32 CPU)

   10:48:53 AM     CPU     %user     %nice   %system   %iowait    %steal     %idle
   10:48:58 AM     all      0.01      0.00      0.03      0.00      0.00     99.96
   Average:        all      0.01      0.00      0.03      0.00      0.00     99.96
   ```

### NetChannel Experiments

- **Figure 6a--6b** (Data copy processing parallelism):

   For read/write syscalls:

   - Server: `./fig6a6b-nc-server.sh`
   - Client: `./fig6a6b-nc-client.sh`

   (On the Server side: type `sudo killall server` to stop the server application.)

   For io_uring:
   
   - Server: `./fig6a6b-nc-uring-server.sh`
   - Client: `./fig6a6b-nc-uring-client.sh`
 
- **Figure 6c** (Network processing parallelism):

   For read/write syscalls:
 
   - Server: `./fig6c-nc-server.sh 1`
   - Client: `./fig6c-nc-client.sh 1`

   (On the Server side: type `sudo killall server` to stop the server application.)

   For io_uring:
 
   - Server: `./fig6c-nc-uring-server.sh 1`
   - Client: `./fig6c-nc-uring-client.sh 1`
    
   **[NOTE]** The argument `1` sets the number of channel. Rerun `./fig6c-nc-server.sh` and `./fig6c-nc-client.sh` with varying the number of channels from `2` to `4` to get the entire Figure 6c results.
    

- **Figure 6d** (Performance isolation):

   For the isolated case:
 
   - Server: `./fig6d-nc-isol-server.sh`
   - Client: `./fig6d-nc-isol-client.sh`

   (On the Server side: type `sudo killall pingpong_server` to stop the server application.)
   
   For the interference case:
 
   - Server: `./fig6d-nc-intf-server.sh`
   - Client: `./fig6d-nc-intf-client.sh`

   (On the Server side: type `sudo killall server pingpong_server` to stop the server application.)


### Default Linux TCP Experiments
 
- **Figure 6a, 6b** (data copy processing parallelism):
 
   For read/write syscalls:

   - Server: `./fig6a6b-tcp-server.sh`
   - Client: `./fig6a6b-tcp-client.sh`

   (On the Server side: type `sudo killall server` to stop the server application.)

   For io_uring:
   
   - Server: `./fig6a6b-tcp-uring-server.sh`
   - Client: `./fig6a6b-tcp-uring-client.sh`


- **Figure 6c** (network processing parallelism):
 
   For read/write syscalls:
 
   - Server: `./fig6c-tcp-server.sh`
   - Client: `./fig6c-tcp-client.sh`

   (On the Server side: type `sudo killall server` to stop the server application.)

   For io_uring:
 
   - Server: `./fig6c-tcp-uring-server.sh`
   - Client: `./fig6c-tcp-uring-client.sh`
    
   **[NOTE]** This result generates the "Without NetChannel" case in Figure 6c.
   
- **Figure 6d** (performance isolation):

   For the isolated case:
 
   - Server: `./fig6d-tcp-isol-server.sh`
   - Client: `./fig6d-tcp-isol-client.sh`

   (On the Server side: type `sudo killall pingpong_server` to stop the server application.)
   
   For the interference case:
 
   - Server: `./fig6d-tcp-intf-server.sh`
   - Client: `./fig6d-tcp-intf-client.sh`

   (On the Server side: type `sudo killall server pingpong_server` to stop the server application.)

    
### Redis Experiment (Figure 7)
 
Download and build Redis.

1. On both sides:

   ```
   cd ~
   git clone https://github.com/qizhe/redis.git
   cd redis/
   make
   ```
   
2. On the Client side:

   ```
   cd ~/redis/deps/hiredis
   make 
   sudo make install
   cd ../../
   g++ redis_async.cpp -levent -levent_core -lhiredis -lpthread -o redis_async
   g++ redis_populate.cpp -levent -lpthread -lhiredis -o redis_populate
   ```

- **Figure 7** (Redis performance):
   - Server: `cd ~/NetChannel/sigcomm22_artifact/; ./fig7-nc-server.sh`
   - Client: `cd ~/NetChannel/sigcomm22_artifact/; ./fig7-nc-client.sh`
 
   **[NOTE]** The client uses 8 threads and each thread queue depth is 1. To tune the queue depth:   
   ```
   taskset -c 0-31:4 ./redis_async 192.168.10.117 6379 8 0.75 1 $QUEUE_DEPTH$
   ```
 
