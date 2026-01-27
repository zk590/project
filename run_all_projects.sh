#!/bin/bash

# 设置脚本执行失败时立即退出
set -e

# 脚本版本
VERSION="1.1.0"

# 颜色定义
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
NC="\033[0m"

# 检查命令是否存在
has_command() {
    command -v "$1" &> /dev/null
    return $?
}

# 执行命令并显示结果
execute() {
    local cmd="$1"
    local desc="$2"
    
    echo -e "\n${BLUE}==> $desc${NC}"
    echo "执行命令: $cmd"
    
    # 执行命令并捕获错误
    if eval "$cmd"; then
        echo -e "${GREEN}✓ 成功${NC}"
        return 0
    else
        echo -e "${RED}✗ 失败${NC}"
        return 1
    fi
}

# 显示帮助信息
show_help() {
    echo -e "${YELLOW}使用方法:${NC} $0 [选项]"
    echo -e "\n${YELLOW}选项:${NC}"
    echo -e "  -h, --help                   显示帮助信息"
    echo -e "  -v, --version                显示脚本版本"
    echo -e "  --app [项目名]               选择性执行application中的项目，多个项目用逗号分隔"
    echo -e "                               可用项目: fibonacci_add, fibonacci_mul, sha2, sha3, keccak, rsa, ecdsa, schnorr, merkle"
    echo -e "                               示例: --app fibonacci_add,fibonacci_mul"
    echo -e "  --sp1 [项目名]               选择性执行sp1-dusk中的项目，多个项目用逗号分隔"
    echo -e "                               可用项目: fibonacci_add, fibonacci_mul, sha2, ecdsa, schnorr, dusk"
    echo -e "                               示例: --sp1 fibonacci_add,fibonacci_mul"
    echo -e "  --aggregation                执行聚合证明生成"
    echo -e "  --all                        执行所有项目（默认行为）"
    echo -e "  --fibonacci-n <数字>         fibonacci_add项目的n参数值（默认: 10）"
    echo -e "  --agg-algorithms <算法列表>  聚合证明的算法列表，多个算法用逗号分隔（默认: fibonacci,fibonacci_mul）"
    echo -e "\n${YELLOW}示例:${NC}"
    echo -e "  $0 --app fibonacci_add,sha2 --sp1 fibonacci_mul"
    echo -e "  $0 --app merkle --aggregation"
    echo -e "  $0 --all --fibonacci-n 20"
}

# 初始化变量
RUN_ALL=true
APP_PROJECTS=()
SP1_PROJECTS=()
RUN_AGGREGATION=false
FIBONACCI_N=10
AGGREGATION_ALGORITHMS="fibonacci,fibonacci_mul"

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                echo "run_all_projects.sh 版本 $VERSION"
                exit 0
                ;;
            --app)
                RUN_ALL=false
                IFS=',' read -r -a APP_PROJECTS <<< "$2"
                shift 2
                ;;
            --sp1)
                RUN_ALL=false
                IFS=',' read -r -a SP1_PROJECTS <<< "$2"
                shift 2
                ;;
            --aggregation)
                RUN_ALL=false
                RUN_AGGREGATION=true
                shift
                ;;
            --all)
                RUN_ALL=true
                shift
                ;;
            --fibonacci-n)
                FIBONACCI_N="$2"
                shift 2
                ;;
            --agg-algorithms)
                AGGREGATION_ALGORITHMS="$2"
                shift 2
                ;;
            *)
                echo -e "${RED}错误: 未知选项 $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
}

# 主函数
main() {
    # 解析命令行参数
    parse_args "$@"
    
    # 确保rust和cargo可用
    if ! has_command cargo; then
        echo -e "${RED}错误: 未找到cargo命令，请安装Rust环境。${NC}"
        exit 1
    fi
    
    # 项目根目录
    ROOT_DIR="/opt/sp10924"
    APPLICATION_DIR="$ROOT_DIR/application"
    DUST_MERKLE_DIR="$ROOT_DIR/dust_merkle"
    SP1_DUSK_DIR="$ROOT_DIR/sp1-dusk"
    
    # 检查项目目录是否存在
    if [ ! -d "$APPLICATION_DIR" ] || [ ! -d "$SP1_DUSK_DIR" ]; then
        echo -e "${RED}错误: 无法找到项目目录，请检查路径是否正确。${NC}"
        exit 1
    fi
    
    # 如果是运行所有项目
    if [ "$RUN_ALL" = true ]; then
        APP_PROJECTS=("fibonacci_add" "fibonacci_mul" "sha2" "sha3" "keccak" "rsa" "ecdsa" "schnorr" "merkle")
        SP1_PROJECTS=("fibonacci_add" "fibonacci_mul" "sha2" "ecdsa" "schnorr" "dusk")
        RUN_AGGREGATION=true
    fi
    
    # 1. 执行application中的项目
    if [ ${#APP_PROJECTS[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}===== 第一步：执行application中的应用项目 =====${NC}"
        
        for project in "${APP_PROJECTS[@]}"; do
            case "$project" in
                fibonacci_add)
                    execute "cd $APPLICATION_DIR/fibonacci_add && cargo run -- --n $FIBONACCI_N" "执行斐波那契加法项目（n=$FIBONACCI_N）"
                    ;;
                fibonacci_mul)
                    execute "cd $APPLICATION_DIR/fibonacci_mul && cargo run" "执行斐波那契乘法项目"
                    ;;
                sha2)
                    execute "cd $APPLICATION_DIR/sha2 && cargo run" "执行SHA2哈希项目"
                    ;;
                sha3)
                    execute "cd $APPLICATION_DIR/sha3 && cargo run" "执行SHA3哈希项目"
                    ;;
                keccak)
                    execute "cd $APPLICATION_DIR/keccak && cargo run" "执行KECCAK哈希项目"
                    ;;
                rsa)
                    execute "cd $APPLICATION_DIR/rsa && cargo run" "执行RSA加密项目"
                    ;;
                ecdsa)
                    execute "cd $APPLICATION_DIR/ecdsa && cargo run" "执行ECDSA签名项目"
                    ;;
                schnorr)
                    execute "cd $APPLICATION_DIR/schnorr && cargo run" "执行Schnorr签名项目"
                    ;;
                merkle)
                    execute "cd $APPLICATION_DIR/merkle && cargo run" "执行Merkle树项目"
                    
                    # 如果执行了merkle项目，自动执行dust_merkle/merkle-plonk项目
                    echo -e "\n${YELLOW}===== 第二步：执行dust_merkle/merkle-plonk生成plonk证明 =====${NC}"
                    execute "cd $DUST_MERKLE_DIR/merkle-plonk && cargo run" "执行Merkle-Plonk证明生成项目"
                    ;;
                *)
                    echo -e "${RED}警告: 未知的application项目 $project，跳过执行。${NC}"
                    ;;
            esac
        done
    fi
    
    # 2. 执行sp1-dusk中的项目
    if [ ${#SP1_PROJECTS[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}===== 第三步：执行sp1-dusk各项目生成sp1证明 =====${NC}"
        
        for project in "${SP1_PROJECTS[@]}"; do
            case "$project" in
                fibonacci_add)
                    execute "cd $SP1_DUSK_DIR/fibonacci_add/script && cargo run" "执行fibonacci-add-program的SP1证明生成"
                    ;;
                fibonacci_mul)
                    execute "cd $SP1_DUSK_DIR/fibonacci_mul/script && cargo run" "执行fibonacci-mul-program的SP1证明生成"
                    ;;
                sha2)
                    execute "cd $SP1_DUSK_DIR/sha2/script && cargo run" "执行sha2-program的SP1证明生成"
                    ;;
                ecdsa)
                    execute "cd $SP1_DUSK_DIR/ecdsa/script && cargo run" "执行ecdsa-program的SP1证明生成"
                    ;;
                schnorr)
                    execute "cd $SP1_DUSK_DIR/schnorr/script && cargo run" "执行schnorr-program的SP1证明生成"
                    ;;
                dusk)
                    execute "cd $SP1_DUSK_DIR/dusk/script && cargo run" "执行dusk-program的SP1证明生成"
                    ;;
                *)
                    echo -e "${RED}警告: 未知的sp1-dusk项目 $project，跳过执行。${NC}"
                    ;;
            esac
        done
    fi
    
    # 3. 执行聚合证明生成
    if [ "$RUN_AGGREGATION" = true ]; then
        echo -e "\n${YELLOW}===== 第四步：执行sp1-dusk/aggregation生成聚合证明 =====${NC}"
        
        # 将逗号分隔的算法列表转换为空格分隔
        ALGORITHMS_SPACE_SEPARATED="$(echo $AGGREGATION_ALGORITHMS | tr ',' ' ')"
        execute "cd $SP1_DUSK_DIR/aggregation/script && cargo run -- --algorithms $ALGORITHMS_SPACE_SEPARATED" "执行SP1聚合证明生成（包含算法: $AGGREGATION_ALGORITHMS）"
    fi
    
    # 检查是否有执行过任何项目
    if [ ${#APP_PROJECTS[@]} -eq 0 ] && [ ${#SP1_PROJECTS[@]} -eq 0 ] && [ "$RUN_AGGREGATION" = false ]; then
        echo -e "\n${RED}错误: 没有指定要执行的项目，请使用--app、--sp1或--all选项。${NC}"
        show_help
        exit 1
    fi
    
    # 检查是否所有命令都执行成功
    echo -e "\n${GREEN}===== 所有任务执行完成 =====${NC}"
}

# 执行主函数
main "$@"