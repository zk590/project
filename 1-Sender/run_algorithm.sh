#!/bin/bash

# 脚本名称: run_algorithm.sh
# 功能: 执行1-Sender项目中的不同算法程序
# 用法: ./run_algorithm.sh <algorithm_name> [algorithm_args...]

# 设置执行目录
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 检查参数
if [ $# -lt 1 ]; then
    echo "用法: ./run_algorithm.sh <algorithm_name> [algorithm_args...]"
    echo ""
    echo "可用算法:"
    echo "  fibonacci_add    - 计算斐波那契数列 (参数: -n <项数>)"
    echo "  fibonacci_mul    - 计算斐波那契数列 (乘法版本)"
    echo "  ecdsa            - ECDSA签名验证 (参数: -m <消息>)
    echo "  ecdsa_batch      - 批量ECDSA签名验证"
    echo "  ecies            - ECIES加密解密"
    echo "  keccak           - Keccak哈希计算"
    echo "  keccak_batch     - 批量Keccak哈希计算"
    echo "  merkle           - Merkle树证明生成"
    echo "  rsa              - RSA签名验证"
    echo "  rsa_batch        - 批量RSA签名验证"
    echo "  schnorr          - Schnorr签名验证"
    echo "  schnorr_batch    - 批量Schnorr签名验证"
    echo "  sha2             - SHA-2哈希计算"
    echo "  sha2_batch       - 批量SHA-2哈希计算"
    echo "  sha3             - SHA-3哈希计算"
    echo "  sha3_batch       - 批量SHA-3哈希计算"
    echo ""
    echo "示例: ./run_algorithm.sh fibonacci_add -n 10"
    echo "      ./run_algorithm.sh ecdsa -m "Hello World"
    exit 1
fi

# 检查是否请求帮助
if [ "$1" = "help" ]; then
    echo "用法: ./run_algorithm.sh <algorithm_name> [algorithm_args...]"
    echo ""
    echo "可用算法:"
    echo "  fibonacci_add    - 计算斐波那契数列 (参数: -n <项数>)"
    echo "  fibonacci_mul    - 计算斐波那契数列 (乘法版本)"
    echo "  ecdsa            - ECDSA签名验证 (参数: -m <消息>)"
    echo "  ecdsa_batch      - 批量ECDSA签名验证"
    echo "  ecies            - ECIES加密解密"
    echo "  keccak           - Keccak哈希计算"
    echo "  keccak_batch     - 批量Keccak哈希计算"
    echo "  merkle           - Merkle树证明生成"
    echo "  rsa              - RSA签名验证"
    echo "  rsa_batch        - 批量RSA签名验证"
    echo "  schnorr          - Schnorr签名验证"
    echo "  schnorr_batch    - 批量Schnorr签名验证"
    echo "  sha2             - SHA-2哈希计算"
    echo "  sha2_batch       - 批量SHA-2哈希计算"
    echo "  sha3             - SHA-3哈希计算"
    echo "  sha3_batch       - 批量SHA-3哈希计算"
    echo ""
    echo "示例: ./run_algorithm.sh fibonacci_add -n 10"
    echo "      ./run_algorithm.sh ecdsa -m \"Hello World\""
    exit 0
fi

# 获取算法名称参数
ALGORITHM="$1"
shift  # 移除第一个参数，剩下的参数传递给算法程序

# 处理算法名称和目录的映射
case "$ALGORITHM" in
    fibonacci_add | fibonacci_mul | ecies | keccak | merkle | rsa | schnorr | sha2 | sha3)
        ALGORITHM_DIR="$BASE_DIR/$ALGORITHM"
        CARGO_COMMAND="cargo run --release"
        ;;
    ecdsa)
        ALGORITHM_DIR="$BASE_DIR/$ALGORITHM"
        CARGO_COMMAND="cargo run --release --bin ecdsa"
        ;;
    ecdsa_batch | keccak_batch | rsa_batch | schnorr_batch | sha2_batch | sha3_batch)
        # 处理批量算法
        BASE_ALGORITHM="${ALGORITHM%%_batch}"
        ALGORITHM_DIR="$BASE_DIR/$BASE_ALGORITHM"
        CARGO_COMMAND="cargo run --release --bin ${ALGORITHM}"
        ;;
    *)
        echo "错误: 未知算法 '$ALGORITHM'"
        echo "请使用以下算法之一: fibonacci_add, fibonacci_mul, ecdsa, ecdsa_batch, ecies, keccak, keccak_batch, merkle, rsa, rsa_batch, schnorr, schnorr_batch, sha2, sha2_batch, sha3, sha3_batch"
        exit 1
        ;;
esac

# 检查算法目录是否存在
if [ ! -d "$ALGORITHM_DIR" ]; then
    echo "错误: 算法目录 '$ALGORITHM_DIR' 不存在"
    exit 1
fi

# 切换到算法目录
cd "$ALGORITHM_DIR" || {
    echo "错误: 无法切换到算法目录 $ALGORITHM_DIR"
    exit 1
}

# 执行算法程序
echo "正在执行算法: $ALGORITHM..."
echo "="

# 执行Cargo命令，传递剩余参数
$CARGO_COMMAND -- "$@"

# 检查执行结果
if [ $? -eq 0 ]; then
    echo ""
    echo "算法执行完成！"
else
    echo ""
    echo "算法执行失败，请检查错误信息。"
    exit 1
fi