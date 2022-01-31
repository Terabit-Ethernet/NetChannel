flows=$1
protocol=$2
nice=$3
i=0
nice -n $nice taskset -c 0-13:4 ./netdriver_test_multithread 192.168.10.117:$((6000+i))  --count $flows "$protocol"pingpong &
