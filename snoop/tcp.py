import imp
import socket
from time import sleep

while 1:
    # 1.创建socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 2. 链接服务器
    server_addr = ("www.baidu.com", 443)
    tcp_socket.connect(server_addr)
    print("Connect")
    # 3. 发送数据
    send_data = "hello~~~"
    tcp_socket.send(send_data.encode("gbk"))
    print("Send")
    # 4. 关闭套接字
    tcp_socket.close()
    sleep(1)