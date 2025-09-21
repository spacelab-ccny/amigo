#!/bin/bash

#################################################################
# Traffic generation script for Amigo
# Example included for evaluation. 
#
# Other parameters may be run in the following manner:
#
# <mobType> <nodeCount> <groupSize> <trafficModel> <runIter>
# <mobType> : mobility model (static, random, chain, march, gather, blockade1, blockade2)
# <nodeCount> : # of nodes in the mobility model
# <groupSize> : group size (number of nodes in each group)
# <trafficModel> : traffic model type (standard or event)
# <runIter> : iteration number (for multiple runs)
#
#################################################################

cd /
source amigo-env/bin/activate
cd /protest/traffic_models


script="/protest/traffic_models/generate-traffic.py"
group_sizes="25"
mobility_models=(static)
traffic_models=(standard)
node_count=100
iters=(100 101 102)


for g in $group_sizes; do
    for mm in $mobility_models; do
        for t in $traffic_models; do
            for n in $node_count; do
                for iter in "${iters[@]}"; do
                    echo "Running: $script $mm $node_count $g $t $iter"
                    python3 "$script" "$mm" "$node_count" "$g" "$t" "$iter"
                done
            done
        done
    done
done
