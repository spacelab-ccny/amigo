#!/bin/bash

#################################################################
# This bash script sets up ns-3 and configures amigo specific
# build options and scripts
#################################################################


cd /ns3

echo "Cleaning..."
./ns3 clean

echo "Configuring..."
./ns3 configure --enable-examples --enable-test

echo "Building..."
./ns3 build

echo "Done building ns-3! Adding amigo specific build configurations..."
cp /protest/arp/arp-cache.cc /ns-3/src/internet/model/arp-cache.cc
cp /protest/routing/normal-50000.cpp /ns3/scratch/normal-50000.cc
cp /protest/routing/normal-500000.cpp /ns3/scratch/normal-500000.cc
cp /protest/routing/normal-5000000.cpp /ns3/scratch/normal-5000000.cc
cp /protest/routing/digest-50000.cpp /ns3/scratch/digest-50000.cc
cp /protest/routing/digest-500000.cpp /ns3/scratch/digest-500000.cc
cp /protest/routing/digest-5000000.cpp /ns3/scratch/digest-5000000.cc
cp /protest/routing/dynamic-50000.cpp /ns3/scratch/dynamic-50000.cc
cp /protest/routing/dynamic-500000.cpp /ns3/scratch/dynamic-500000.cc
cp /protest/routing/dynamic-5000000.cpp /ns3/scratch/dynamic-5000000.cc
cp /protest/routing/static-50000.cpp /ns3/scratch/static-50000.cc
cp /protest/routing/static-500000.cpp /ns3/scratch/static-500000.cc
cp /protest/routing/static-5000000.cpp /ns3/scratch/static-5000000.cc

echo "Building..."
./ns3 build

echo "Amigo build done!"
