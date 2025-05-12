# RIPEMD-160 Hash <-> Bitcoin P2PKH Address Converter

一个用于在RIPEMD-160哈希值和比特币P2PKH地址之间进行转换的工具。

## 功能

- 将RIPEMD-160哈希值转换为比特币P2PKH地址
- 将比特币P2PKH地址转换回RIPEMD-160哈希值
- 支持从文件批量转换
- 支持直接输入字符串转换

## 安装

### 前提条件

- GCC或其他C编译器
- OpenSSL开发库

### 构建方法

```bash
# 安装依赖(Ubuntu/Debian)
sudo apt-get install build-essential libssl-dev

# 构建项目
make
```

## 使用方法

```bash
./hash160_converter [options]
```

### 选项

- `-p` : 将RIPEMD-160哈希转换为P2PKH地址
- `-r` : 将P2PKH地址转换为RIPEMD-160哈希
- `-f <file>` : 输入文件（每行一个条目）
- `-s <string>` : 输入字符串（要转换的哈希或地址）
- `-o <file>` : 输出文件（默认：标准输出）
- `-h` : 显示帮助信息

### 示例

将单个RIPEMD-160哈希转换为P2PKH地址:
```bash
./hash160_converter -p -s 0000000000000000000000000000000000000000
```

将单个P2PKH地址转换为RIPEMD-160哈希:
```bash
./hash160_converter -r -s 1111111111111111111114oLvT2
```

批量转换文件中的哈希值:
```bash
./hash160_converter -p -f hashes.txt -o addresses.txt
```

批量转换文件中的地址:
```bash
./hash160_converter -r -f addresses.txt -o hashes.txt
```

## P2PKH地址格式说明

比特币P2PKH（Pay to Public Key Hash）地址是由以下步骤生成的:

1. 从公钥生成RIPEMD-160哈希（先SHA-256，然后RIPEMD-160）
2. 添加版本字节（0x00表示比特币主网）
3. 计算校验和（双SHA-256的前4个字节）
4. 将版本+哈希+校验和经过Base58编码

结果是以"1"开头的比特币地址。

## 安全提示

此工具仅用于教育目的。请勿将其用于存储实际的加密货币资产。 