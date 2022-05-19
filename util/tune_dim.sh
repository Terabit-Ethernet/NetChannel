usec=$1
frames=$2
ethtool -C ens2f0  adaptive-rx off adaptive-tx off
ethtool -C ens2f0  tx-usecs $usec tx-frames $frames rx-usecs $usec rx-frames $frames
