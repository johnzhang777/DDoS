#!/bin/bash

# 清除 Mininet 环境
echo "清除 Mininet 环境..."
sudo mn -c

# 启动 Ryu 控制器
echo "启动 Ryu 控制器..."
ryu-manager net/controller.py &

# 等待 Ryu 控制器启动
sleep 3  # 可以根据需要调整等待时间

# 运行主程序
echo "运行主程序..."
python3 main.py