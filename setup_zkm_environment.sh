#!/bin/bash

# 设置zkm-toolchain环境变量
export PATH=/root/.zkm-toolchain/bin:/root/.zkm-toolchain/rust-toolchain-x86-64-unknown-linux-gnu-20251217/bin:$PATH
export ZIREN_ZKM_CC=mipsel-zkm-zkvm-elf-gcc

echo "zkm-toolchain环境变量已设置："
echo "PATH=$PATH"
echo "ZIREN_ZKM_CC=$ZIREN_ZKM_CC"
echo ""
echo "要永久保存这些环境变量，请将上述export命令添加到/root/.bashrc文件中："
echo "echo 'export PATH=/root/.zkm-toolchain/bin:/root/.zkm-toolchain/rust-toolchain-x86-64-unknown-linux-gnu-20251217/bin:$PATH' >> /root/.bashrc"
echo "echo 'export ZIREN_ZKM_CC=mipsel-zkm-zkvm-elf-gcc' >> /root/.bashrc"
echo ""
echo "然后执行 source /root/.bashrc 使配置生效"