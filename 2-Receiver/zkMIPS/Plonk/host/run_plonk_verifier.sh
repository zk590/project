#!/bin/bash

# 检查是否提供了算法名参数
if [ $# -eq 0 ]; then
    echo "Usage: $0 <algorithm_name>"
    echo "Example: $0 fibonacci-add"
    exit 1
fi

# 获取算法名参数
ALGORITHM_NAME=$1

# 执行cargo run命令，传入算法名参数
echo "Running Plonk verifier for algorithm: $ALGORITHM_NAME"
cd /opt/project/2-Receiver/zkMIPS/Plonk/host && cargo run -- --algorithm "$ALGORITHM_NAME"