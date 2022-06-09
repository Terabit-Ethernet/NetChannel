## SIGCOMM 2022 Artifact Evaluation

### MPTCP configurations

   On both sides:

   1. Edit `/etc/default/grub` to boot with mptcp kernel by default. For example:  

   ```
   GRUB_DEFAULT="1>Ubuntu, with Linux 4.19.155-mptcp+"
   ```

   2. Update the grub configuration and reboot into the new kernel.  

   ```
   update-grub && reboot
   ```
   
   3. Download the script and run the configuration:

   ```
   cd ~
   git clone https://github.com/qizhe/Understanding-network-stack-overheads-SIGCOMM-2021
   cd Understanding-network-stack-overheads-SIGCOMM-2021/
   sudo ./mptcp_setup
   ```
   
   4. Chabge the number of subflows <#subflows>: `2, 4, 8` to get the MPTCP result in Figure 2.
   ```
   sudo echo <#subflows> > /sys/module/mptcp_fullmesh/parameters/num_subflows
   ```
   
   On the Server side:
   
   ```
   cd script/
   bash receiver/single-flow_mptcp.sh
   ```
   
   On the Client side:
   
   ```
   cd script/
   bash sender/single-flow_mptcp.sh
   ```

