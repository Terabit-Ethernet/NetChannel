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
   
3. When system is rebooted, run the configuration script:

   ```
   sudo ~/NetChannel/scripts/network_setup.sh ens2f0
   sudo ~/NetChannel/scripts/mptcp_setup
   cd ~/NetChannel/sigcomm22_artifact/fig2_mptcp/
   ```
   
- **Figure 2** (Lack of scalability for long flows):

   **[NOTE]** Repeat the following experiment with varying <#subflows>: `2, 4, 8` to get the MPTCP result in Figure 2.

   - Both: `sudo -s; echo <#subflows> > /sys/module/mptcp_fullmesh/parameters/num_subflows; exit`

   - Server: `./fig2-arfs-mptcp-server.sh`
   - Client: `./fig2-arfs-mptcp-client.sh`

   (Server: `sudo killall iperf` to stop the server application.)

