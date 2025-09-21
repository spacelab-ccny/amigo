#!/bin/bash

#################################################################
# This bash script sets up the docker container for amigo
#################################################################


docker build -t amigo .

docker run -it  \
-v $(pwd)/protest:/protest \
-v $(pwd)/runners:/runners \
amigo /bin/bash
