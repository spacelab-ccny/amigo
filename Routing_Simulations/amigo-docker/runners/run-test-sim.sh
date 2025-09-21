#!/bin/bash

#################################################################
# 
# This bash script runs amigo routing simulations;
# we provide an example with parameters
# which should complete in a reasonable amount of time (< 1 hour)
#
# Other parameters may be run in the following manner, if 
# corresponding mobility models and traffic models have been generated:
# 
# <nodeCount> <buffSize> <trafficModel> <mobilityModel> <groupSize> <runIter>
# <nodeCount> : # of nodes in the sim
# <buffSize> : buffer size (bytes)
# <trafficModel> : traffic model type (standard or event)
# <mobilityModel> : mobility model (static, random, chain, march, gather, blockade1, blockade2)
# <groupSize> : group size (number of nodes in each group)
# <runIter> : iteration number (for multiple runs)
# 
#################################################################

cd /ns3

routing="dynamic"
nodeCount=100
buffSize=(50000)
trafficModel="standard"
mobilityModels=(chain)
groupSize=25
runIter=(1)

timestamp=$(date +%Y%m%d_%H%M%S)
log_dir="logs_$timestamp"
mkdir -p "$log_dir"

job_count=0
max_jobs=15

for mo in "${mobilityModels[@]}"; do
    for iter in "${runIter[@]}"; do
        log_file="$log_dir/${routing}_nc${nodeCount}_bs${buffSize}_mo${mo}_gs${groupSize}_iter${iter}.log"

        echo "Starting job: $mo, iter=$iter (logging to $log_file)"

        nohup ./ns3 run scratch/$routing-${buffSize} -- \
            $nodeCount $trafficModel $mo $groupSize $iter \
            > "$log_file" 2>&1 &

        ((job_count++))

        if ((job_count >= max_jobs)); then
            wait -n
            ((job_count--))
        fi
    done
done

wait
echo "All jobs completed at $(date)" | tee "$log_dir/complete.txt"
