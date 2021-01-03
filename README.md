# net-driver_impl
Assuming we have two servers,
1. Compile and Load net-driver kernel module:
 
   ```
   make
   sudo insmod nd_module.ko
   '''
2. Initiate ND Conns
   ```
   sudo ./run_module.sh
   ```
3. Compile sample apps from /util
4. In the server side, 
   ```
   taskset -c $CORE ./server --ip 192.168.10.117 --port 4000
   ```
5. In the client side,
  ```
  sudo -s
  taskset -c 28 ./netdriver_test 192.168.10.117:4000 --sp 1000 --count 10  ndping
  ```
6. 
