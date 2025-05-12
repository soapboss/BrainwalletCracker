# 队列执行脚本使用说明

这个脚本用于自动执行brainflayer_sha256程序处理dic目录下的文件，并在发现哈希变动时发送邮件通知。

## 功能
- 监控dic目录中的文件并按顺序处理
- 记录已处理的文件到old.txt
- 监控found.hash文件内容变化（通过SHA256验证）并发送邮件通知
- 自动检测新添加的文件并加入处理队列
- 当found.hash文件内容变化时，自动将其复制到found目录并以SHA256哈希值命名

## 环境变量设置

在使用前，请确保设置以下环境变量:

```bash
export SENDER_EMAIL="your_email@example.com"
export SENDER_PASSWORD="your_email_password"
```

可以将其添加到~/.bashrc文件中永久保存。

## 使用方法

1. 确保dic目录已创建
2. 将要处理的文件放入dic目录
3. 运行脚本:

```bash
cd /path/to/brainflayer-master/mode1
python3 queue_executor.py
```

## 注意事项

- 脚本会持续运行并监控dic目录的变化
- 如需停止脚本，请使用Ctrl+C
- 已处理的文件名会保存在old.txt中
- 发现的哈希会保存在found目录下，文件名格式为"[SHA256哈希值].hash" 


export SENDER_EMAIL="your_email@example.com"
export SENDER_PASSWORD="your_email_password"