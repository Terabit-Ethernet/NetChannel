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
 
 8. Run parallel data copy processing exp,
 Server:
 ```
 sudo ./run_single_flow_set_up.sh 
 cd util/
 ./run_single_server.sh 1

```
 Client:
 ```
 sudo ./run_single_flow_set_up.sh 
 cd util/
 ./run_client.sh 1
```
 9. Run parallel network processing exp,
 Server:
 ```
 sudo ./run_np.sh 
 cd util/
 ./run_np_server.sh 1

```
 Client:
 ```
 sudo ./run_np.sh 
 cd util/
 ./run_pingpong_setup3.sh 1 nd
```
