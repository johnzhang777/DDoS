#!/bin/bash

echo "Clean Mininet environment..."
sudo mn -c

echo "Strt Ryu controller..."
ryu-manager net/controller.py &

# wait for Ryu to start
sleep 3  

echo "Run main.py..."
python3 main.py