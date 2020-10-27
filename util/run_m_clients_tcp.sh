CORES=$1
core=0

while (( core < CORES ));do
    ./run_client_tcp.sh $CORES $core
    (( core++ ))
done
