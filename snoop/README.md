# 基于BCC框架的进程资源监控程序

## 1. 用法

usage: top_snoop.py [-h] [-p PID] [-c COMMAND] [-i INTERVAL]

Attach to process and snoop its resource usage

optional arguments:
  -h, --help            show this help message and exit
  -p PID, --pid PID     id of the process to trace (optional)
  -c COMMAND, --command COMMAND
                        execute and trace the specified command
  -i INTERVAL, --interval INTERVAL
                        The interval of snoop

## 2. 各模块说明

### 2.1 TopSnoop

顶层监控模块，集成各部分不同资源的监控模块。

处理输入参数，如果带有 `-c`参数则启动子进程运行该程序并获取pid。

创建各个资源监控模块，并开启进程运行。

### 2.2 CPUSnoop

进程CPU占用监控模块。

在finish_task_switch处插桩统计进程的运行时间与非运行时间。

### 2.3 MemSnoop

进程内存占用监控模块。

在用户态内存分配相关的函数处插桩以统计内存的申请与释放。

### 2.4 NetworkSnoop

进程网络流量监控模块。

在网络层针对ip数据包的收发进行监控，监控进程的网络流量情况。
