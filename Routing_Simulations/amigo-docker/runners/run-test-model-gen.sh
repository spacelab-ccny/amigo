#!/bin/bash

#################################################################
#
# Minimal runner for Amigo mobility generator. 
# Example included for evaluation. 
#
# Other parameters may be run in the following manner:
#
# <mobType> <nodeCount> <runIter> <seconds>
# <mobType> : mobility model (static, random, chain, march, gather, blockade1, blockade2)
# <nodeCount> : # of nodes in the mobility model
# <runIter> : iteration number (for multiple runs)
# <seconds> : duration of the simulation in seconds
#
# You will likely want to change other parameters within the
# relevant python script to generate different scenarios.
# For example, the total space occupied by the protest is parameterizable.
# These areas in the code are clearly labeled; and accompanying 
# animation files can be used to determine the feasibility of
# your produced mobility model.
#
#################################################################

cd /

source amigo-env/bin/activate

cd /protest/mobility_models


script="/protest/mobility_models/generate-mobility.py"
mobtype=(static)
nodecounts=(100)
iters=(100 101 102)
simlen=3600

for rt in "${mobtype[@]}"; do
  for n in "${nodecounts[@]}"; do
    for it in "${iters[@]}"; do
      echo "python3 $script $rt $n $it $simlen"
      python3 "$script" "$rt" "$n" "$it" "$simlen"
    done
  done
done