import imp
import socket
from time import sleep
from ctypes import *


mem = None

def dynamicMemory():
    global mem
    # 在这里申请1M的内存，单位k
    mem = create_string_buffer(1024 * 1024)
    return mem

def freeMemory():
    global mem
    mem = None

cnt = 0
while 1:
    # 1.创建socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 2. 链接服务器
    server_addr = ("www.baidu.com", 443)
    tcp_socket.connect(server_addr)
    # print("Connect")
    # 3. 发送数据
    send_data = "hello~~~"
    tcp_socket.send(send_data.encode("gbk"))
    # print("Send")
    # 4. 关闭套接字
    tcp_socket.close()
    # 内存申请与释放部分
    dynamicMemory()
    cnt+=1
    sleep(1)
    if cnt > 100:
        freeMemory()
        cnt = 0
    # 高CPU占用部分
    tmp = 0
    for i in range(999999):
        tmp += i
    
    sleep(1)