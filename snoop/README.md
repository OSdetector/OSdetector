# 基于BCC框架的进程资源监控程序

## 1. 用法

```shell

Attach to process and snoop its resource usage

optional arguments:
  -h, --help            show this help message and exit
  -p PID, --pid PID     id of the process to trace (optional)
  -c COMMAND, --command COMMAND
                        execute and trace the specified command (optional)
  -i INTERVAL, --interval INTERVAL
                        The interval of snoop (unit:s)
```

## 2. 各模块说明

### 2.1 TopSnoop

顶层监控模块，集成各部分不同资源的监控模块。

处理输入参数，如果带有 `-c`参数则启动子进程运行该程序并获取pid。

创建各个资源监控模块，并开启进程运行。

创建或根据pid找到监控进程。

输出说明：

- CPU占用监控模块输出到cpu.csv文件；
- 内存占用监控模块输出到mem.csv文件；
- 流量监控模块输出到network.csv文件；
- 系统调用监控模块输出到syscall.csv文件；

### 2.2 CPUSnoop

进程CPU占用监控模块。

在finish_task_switch处插桩统计进程的运行时间。

前端定期唤醒并从eBPF虚拟机中获取进程运行时间数据，然后以唤醒周期为总CPU时间计算监控进程CPU占用率。


输出说明：

- Ticks：本次输出时的时间（当值为END时代表进程退出）
- PID：监控进程的PID
- COMM：启动本次进程的命令
- ON CPU：进程运行时间
- OFF CPU：进程非运行时间
- CPU%：进程CPU占用率

### 2.3 MemSnoop

进程内存占用监控模块。

在用户态内存分配释放相关的函数处插桩以统计内存的申请与释放。

前端定期唤醒并从eBPF虚拟中获取监控进程当前仍未释放的内存申请数量与内存占用大小。


输出说明：

- ticks：本次输出时的时间（当值为END时代表进程退出）
- size(B)：当前进程占用的内存大小，单位为字节
- times：当前进程仍未释放的内存申请次数

### 2.4 NetworkSnoop

进程网络流量监控模块。

在数据链路层进行插桩监控进程流量。

进程定期唤醒并从eBPF虚拟机中获取监控进程在当前周期中的流量情况。


输出说明：

- Ticks：本次输出时的时间（当值为END时代表进程退出）
- PID：监控进程的PID
- COMM：启动本次进程的命令
- RX_KB：进程接受流量，单位为KB
- TX_KB：进程发送流量，单位为KB

### 2.5 SyscallSnoop

进程系统调用监控模块。

通过在raw_syscalls:sys_enter和raw_syscalls:sys_exit处插桩获取进程进入和退出的系统调用。


输出说明：

- Ticks：本次输出时的时间（当值为END时代表进程退出）
- PID：监控进程的PID
- COMM：启动本次进程的命令
- ACTION：取值为{ENTER，LEAVE}，表示进程进入或退出某个系统调用
- SYSCALL_ID：系统调用号
- RET：系统调用返回值
