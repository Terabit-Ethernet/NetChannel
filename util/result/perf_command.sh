CORE=$1
sudo ./perf record -C $CORE -g -F 99 -- sleep 30
sudo ./perf script | ./FlameGraph/stackcollapse-perf.pl > out.perf-folded
sudo ./FlameGraph/flamegraph.pl out.perf-folded > perf-kernel.svg 
