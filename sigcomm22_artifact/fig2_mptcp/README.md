## SIGCOMM 2022 Artifact Evaluation

### MPTCP configurations

On both sides:

1. `sudo vi /etc/default/grub` to boot with mptcp kernel by default. For example:  

   ```
   GRUB_DEFAULT="1>Ubuntu, with Linux 4.19.155-mptcp+"
   ```

2. Update the grub configuration and reboot into the new kernel.  

   ```
   sudo -s
   update-grub && reboot
   ```
   
3. Download MPTCP scripts:

   ```
   cd ~
   git clone https://github.com/qizhe/Understanding-network-stack-overheads-SIGCOMM-2021
   ```

4. Run the configuration script:

   ```
   cd ~/Understanding-network-stack-overheads-SIGCOMM-2021/
   sudo ./mptcp_setup
   cd scripts/
   ```
   
- **Figure 2** (Lack of scalability for long flows):

   **[NOTE]** Repeat the following experiment with varying <#subflows>: `2, 4, 8` to get the MPTCP result in Figure 2.

   - Both: `sudo echo <#subflows> > /sys/module/mptcp_fullmesh/parameters/num_subflows`

   - Server: `receiver/single-flow_mptcp.sh`
   - Client: `sender/single-flow_mptcp.sh`
