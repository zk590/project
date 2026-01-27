#!/bin/bash

# 脚本名称: run_verifier.sh
# 功能: 执行zkVM验证器程序，验证指定算法的证明文件
# 用法: ./run_verifier.sh zkvm <algorithm_name>

# 设置执行目录
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 检查参数
if [ $# -lt 2 ]; then
    echo "用法: ./run_verifier.sh zkvm <algorithm_name>"
    echo "示例: ./run_verifier.sh zkvm fibonacci_add"
    echo "可用算法: fibonacci_add, fibonacci_mul, ecdsa, ecies, keccak, merkle, rsa, schnorr, sha2, sha3"
    exit 1
fi

# 获取参数
VM_TYPE="$1"
ALGORITHM="$2"

# 检查是否指定了zkvm
if [ "$VM_TYPE" != "zkvm" ]; then
    echo "错误: 目前只支持 'zkvm' 验证器类型"
    echo "用法: ./run_verifier.sh zkvm <algorithm_name>"
    exit 1
fi

# 切换到zkVM脚本目录
ZKVM_DIR="$BASE_DIR/zkVM/script"
cd "$ZKVM_DIR" || {
    echo "错误: 无法切换到zkVM脚本目录 $ZKVM_DIR"
    exit 1
}

# 执行验证器程序
echo "正在使用 $VM_TYPE 验证器验证算法: $ALGORITHM 的证明文件..."
echo "="

# 使用cargo run执行程序，传递算法名称参数
cargo run --release -- "$ALGORITHM"

# 检查执行结果
if [ $? -eq 0 ]; then
    echo ""
    echo "验证完成！"
else
    echo ""
    echo "验证失败，请检查错误信息。"
    exit 1
fi