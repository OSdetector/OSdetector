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

创建各个资源监控模块，并开启进程运行。

### 2.2 CPUSnoop

进程CPU占用监控模块。

在finish_task_switch处插桩统计进程的运行时间与非运行时间。

TODO：目前每个统计周期得到的运行时间波动较大，虽然按照运行时间/(运行时间+非运行时间)依然可以得到较高占用率，但是不够准确。

### 2.3 MemSnoop

进程内存占用监控模块。

在用户态内存分配相关的函数处插桩以统计内存的申请与释放。

### 2.4 NetworkSnoop

进程网络流量监控模块。

在TCP的收发数据包处插桩统计流量。

TODO：

1. 目前无法对NET.c程序的流量进行监控，可能是因为调用curl开启的是一个子进程。目前无法对子进程同时进行监控。
2. 目前仅完成对TCP数据包的监控，或许需要再考虑UDP数据包。
