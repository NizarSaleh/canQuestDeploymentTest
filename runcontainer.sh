#!/bin/bash
set -e  # Exit on error

# 1) Load the vcan kernel module
sudo modprobe vcan

# 2) Create the vcan0 interface only if it doesn't already exist
if ! ip link show vcan0 &> /dev/null
then
  sudo ip link add dev vcan0 type vcan
fi

# 3) Bring up vcan0
sudo ip link set vcan0 up

# 4) Remove any existing container named "my_can_server"
sudo docker rm -f my_can_server 2>/dev/null || true

# 5) Run the container. 
#    If your Dockerfile CMD is ["python","old_uds_server.py","vcan0"], 
#    then do NOT pass "vcan0" again on the command line!
sudo docker run -it \
    --name my_can_server \
    --network host \
    --cap-add=NET_ADMIN \
    can-server

