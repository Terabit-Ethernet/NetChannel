flows=$1
nice=$2
i=0
while (( i < flows ));do
	nice -n $nice taskset -c $((i * 4)) ./netdriver_test 192.168.10.117:$((5000+i)) --sp $((6000+i)) --count 1 whileloop &
    (( i = 1 + i ))
done
