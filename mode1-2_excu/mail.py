import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_success_email(password, file_name):
    # 从环境变量中获取邮箱地址和密码
    sender_email = os.getenv("SENDER_EMAIL")
    sender_password = os.getenv("SENDER_PASSWORD")
    receiver_email = "soapboss@163.com"  # 接收者邮箱地址

    if not sender_email or not sender_password:
        print("环境变量 SENDER_EMAIL 和 SENDER_PASSWORD 未设置。")
        return

    # 创建邮件内容
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "大饼地址已发现 请及时处理"

    body = f"大饼地址已发现 请及时处理 请查看本机的地址  重要信息请马上处理 "
    message.attach(MIMEText(body, "plain"))

    # 连接到SMTP服务器并发送邮件
    try:
        with smtplib.SMTP_SSL("smtp.163.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("邮件发送成功！")
    except Exception as e:
        print(f"邮件发送失败: {e}")

if __name__ == "__main__":
    # 测试部分
    test_password = "test_password"
    test_file_name = "test_file.txt"
    
    print("发送成功邮件测试...")
    send_success_email(test_password, test_file_name)


# 示例调用
# send_success_email("your_password_here", "your_file_name_here")
# send_failure_email("your_file_name_here")

#环境变量设置
'''

nano ~/.bashrc
export SENDER_EMAIL="soapboss000@163.com"
export SENDER_PASSWORD="YGScpCCe7xzNmf8v"

source ~/.bashrc


# Email Configuration
SENDER_EMAIL=soapboss000@163.com
SENDER_PASSWORD=YGScpCCe7xzNmf8v
RECEIVER_EMAIL=soapboss@163.com

'''

