FROM ubuntu:22.04

LABEL maintainer="sradway@g.harvard.edu"
LABEL description="This is a custom Docker Image for running Amigo simulations!"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt install -y git build-essential python3 python3-pip python3-setuptools python3-dev cmake wget software-properties-common gcc-11 g++-11 && \
    add-apt-repository ppa:ubuntu-toolchain-r/test && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 11 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 11 && \
    apt clean 

RUN git clone https://gitlab.com/nsnam/ns-3-dev.git /ns3