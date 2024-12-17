#!/bin/bash

export PYTHONPATH=$PYTHONPATH:$(pwd)

echo "Clean Mininet environment..."
sudo mn -c

echo "Start Ryu controller..."
ryu-manager net/controller.py &

# wait for Ryu to start
sleep 3  

echo "Running main.py..."
python3 main.py