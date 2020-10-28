CORES=$1
score=$2
core_id=0
while (( core_id < CORES ));do
	taskset -c $core_id ./netdriver_test 192.168.10.117:$((4000+score)) --sp $(( 1000 * (1 + score) +  core_id )) --count 40  ndping &
        (( core_id++ ))
done
