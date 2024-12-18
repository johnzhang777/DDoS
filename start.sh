#!/bin/bash

# kill previous process
PORT=12345
PID=$(lsof -ti :$PORT)

if [ -n "$PID" ]; then
    echo "kill $PID"
    kill -9 $PID
else
    echo "No process found listening on port $PORT."
fi

sleep 1


export PYTHONPATH=$PYTHONPATH:$(pwd)


echo "Clean Mininet environment..."
sudo mn -c

echo "Start Ryu controller..."
ryu-manager net/controller.py &

# wait for Ryu to start
sleep 2

echo "Running main.py..."
python3 main.py