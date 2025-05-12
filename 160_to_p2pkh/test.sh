#!/bin/bash
# 测试RIPEMD-160哈希和P2PKH地址转换器的脚本

echo "===== 编译程序 ====="
make

echo -e "\n===== 测试1: 单个哈希转地址 ====="
./hash160_converter -p -s 62e907b15cbf27d5425399ebf6f0fb50ebb88f18

echo -e "\n===== 测试2: 单个地址转哈希 ====="
./hash160_converter -r -s 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

echo -e "\n===== 测试3: 批量哈希转地址 ====="
./hash160_converter -p -f test_addresses.txt | head -5

echo -e "\n===== 测试4: 批量地址转哈希 ====="
./hash160_converter -r -f test_addresses.txt | head -5

echo -e "\n===== 测试完成 ====="
echo "你可以尝试以下命令来进一步测试程序:"
echo "./hash160_converter -p -s <你的RIPEMD-160哈希>"
echo "./hash160_converter -r -s <你的比特币P2PKH地址>" 