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
      
2. Compile and load net-driver kernel module:
 
   ```
   make
   sudo insmod nd_module.ko
   ```
   
   Configure your NIC:
   
   ```
   sudo ./network_setup.sh $IP $IFACE_NAME
   ```
   eg. client: `sudo ./network_setup.sh 192.168.10.116 ens2f0` and the server `sudo ./network_setup.sh 192.168.10.117 ens2f0`.
   
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
 
## 3. SIGCOMM 2022 Artifact Evaluation
 
 After successfully loading and running modules,
 
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
