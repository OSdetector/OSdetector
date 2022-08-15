# 新版监控模块

## 1 特性

- 单进程程序，只启动1次BCC，减小内存占用；
- 模块化组织程序，通过配置文件 `config.json`控制模块加载；

## 2 文件说明

```
.
├── config.json				# 配置文件，设置监控模块与输出文件路径
├── cpu.csv				# 进程CPU占用监控模块输出文件
├── cpu_snoop.py			# 基于BCC框架的进程CPU占用监控模块
├── cpu_snoop_stat.py			# 基于读取/proc/<pid>/stat的进程CPU占用监控模块
├── cpu_snoop_top.py			# 基于top工具的进程CPU占用监控模块
├── mem.csv				# 进程内存占用监控模块输出文件
├── mem_snoop.py			# 基于BCC框架的进程内存占用监控模块
├── probe.py				# 基于BCC框架的用户函数执行情况检测模块
├── trace.py				# 基于BCC框架的用户函数执行跟踪模块
├── net.csv				# 进程流量监控模块输出文件
├── network_snoop.py			# 基于BCC框架的进程流量监控模块
├── README.md				# 本文件
├── run.sh				# 启动脚本
├── syscall.csv				# 进程系统调用监控模块输出文件
├── syscall_snoop.py			# 基于BCC框架的进程系统调用监控模块
├── top_snoop.py			# 顶层集成模块
└── utils.py				# 相关helper函数
```

## 3 配置文件说明

```json
{
    "snoop_cpu": "None",  				# 进程CPU占用监控模块，可选项为("bcc", "stat", "top", null)   
    "cpu_output_file": "cpu.csv", 			# 进程CPU占用输出文件名
    "snoop_mem": "None",  				# 进程内存占用监控模块，可选项为("bcc", null)
    "mem_output_file": "mem.csv", 			# 进程内存占用输出文件名
    "probes":{						# 用户态函数执行情况统计，包括内存占用变化，CPU时间分布
        "event_name":["./mem_example/main:func1"],  	# 检测的函数挂载点，bin:func
        "output_file":"tmp.csv",			# 输出文件
	"spid":10000					# 对某个特定线程进行监控，spid为线程id，填入null表示不启用
    },
    "trace": {						# 用户态函数执行跟踪
        "tracee_name":["./test/search:search"],		# 检测的函数挂载点，bin:func
        "output_file":"trace_output",			# 输出文件
        "enter_msg_format":["'Enter search, n=%d' % (arg1)"], 	# 进入函数时输出的消息，支持的参数为arg1-arg6，类型为数字或字符串
        "return_msg_format":["Return search"]			# 函数返回时输出的消息，支持的参数为retval
	"spid":10000					# 对某个特定线程进行监控，spid为线程id，填入null表示不启用
    },
    "snoop_network": "bcc_user", 			# 进程网络流量监控模块，可选项为("bcc_user", "bcc_kernel", null)
    "network_output_file": "net.csv", 			# 进程流量监控输出文件名
    "snoop_syscall": "None", 				# 系统占用监控模块，可选项为("bcc", null)
    "syscall_output_file": "syscall.csv",		# 进程系统调用输出文件名
    "interval": 5,  					# 监控周期，单位秒
    "trace_multiprocess":  true, 			# 是否跟踪并监控进程产生的子进程（对系统调用监控输出会破坏原有顺序）
    "show_all_threads": true				# 是否分别展示每个线程，设定为true输出文件中的PID属性改为SPID（线程号）
}
```

## 4 各模块说明

### 4.1 顶层集成模块

顶层集成模块用于将各个模块集成起来，提供输入处理，eBPF虚拟机启动等功能。

### 4.2 进程CPU占用监控模块

输出说明

- TIME：本次输出时的时间（当值为END时代表进程退出）
- PID：监控进程的PID
- COMM：启动本次进程的命令
- ON CPU：进程运行时间，单位（ms）。使用top模块获取占用率时该项恒为-1.
- OFF CPU：进程非运行时间，单位（ms）。使用top模块获取占用率时该项恒为-1.
- CPU%：进程CPU占用率

启用多进程选项后，同一时间戳下会有多行数据对应不同进程。

#### 4.2.1 BCC

进程CPU占用监控模块。

在finish_task_switch处插桩统计进程的运行时间。

前端定期唤醒并从eBPF虚拟机中获取进程运行时间数据，然后以唤醒周期为总CPU时间计算监控进程CPU占用率。

#### 4.2.2 stat

进程CPU占用监控模块。

通过在两个时间点访问 `/proc/<pid>/stat`获取进程的运行时间，做差得到进程在该周期的运行时间。

周期时间通过计算两次采样的时间差获得。

**TODO:**

在总时间的采样上，目前采用的方案是记录2次采样的时间做差得到，在CPU占用较高的情况下会出现占用率超过100%的情况；

另一种方案是通过 `/proc/stat`获得两次采样之间CPU运行时间的差值，但是这个差值是所有CPU核的总和，与现有分母为单个CPU运行时间冲突；直接除以核数也会造成占用率超过100%。

##### 4.2.3 top

进程CPU占用监控模块。

通过调用top工具获取进程的CPU占用情况。

### 4.3 进程内存占用监控模块

进程内存占用监控模块。

目前分别在标准库函数与内核中进行插桩记录。

前端定期唤醒并从eBPF虚拟中获取监控进程当前仍未释放的内存栈数量与内存占用大小。

输出说明：

- TIME：本次输出时的时间（当值为END时代表进程退出）
- SIZE(B)：当前进程占用的内存大小，单位为字节
- NUM：当前进程仍未释放的内存申请次数

启用多进程选项后，同一时间戳下会有多行数据对应不同进程。

### 4.4 进程流量监控模块

进程网络流量监控模块。

在数据链路层进行插桩监控进程流量。

进程定期唤醒并从eBPF虚拟机中获取监控进程在当前周期中的流量情况。

输出说明：

- TIME：本次输出时的时间（当值为END时代表进程退出）
- PID：监控进程的PID
- COMM：启动本次进程的命令
- RX_KB：进程接受流量，单位为KB
- TX_KB：进程发送流量，单位为KB

启用多进程选项后，同一时间戳下会有多行数据对应不同进程。

### 4.5 进程系统调用监控模块

进程系统调用监控模块。

通过在raw_syscalls:sys_enter和raw_syscalls:sys_exit处插桩获取进程进入和退出的系统调用。

输出说明：

- TIME：本次输出时的时间（当值为END时代表进程退出）
- PID：监控进程的PID
- COMM：启动本次进程的命令
- ACTION：取值为{0：ENTER，1：LEAVE}，表示进程进入或退出某个系统调用
- SYSCALL_ID：系统调用号
- PARM1：该系统调用的第1个参数，仅支持数值型。

### 4.6 用户函数运行分析工具Probe

根据用户指定的函数挂载点，在进入函数与函数返回时分别插桩，获取函数运行期间内存占用的变化和CPU时间的分布情况；

输出说明：

- PID
- Event Name：挂载函数名;
- Size：函数执行后内存占用大小的变化，单位B;
- Number of Allocs：函数执行后内存占用栈的数量变化;
- utime：函数执行期间用户态时间，单位ms;
- stime：函数执行期间内核态时间，单位ms;
- nvcsw：函数执行期间自愿上下文切换次数;
- nivcsw：函数执行期间非自愿上下文切换次数;
- ENTER TIME：进入函数调用的时间
- RETURN TIME：从函数调用返回的时间
- time：函数从进入到返回经历的时间;

### 4.7 用户程序跟踪工具trace

根据用户指定函数挂载点，在进入与返回函数处插桩，记录时间与用户指定的参数，输出到文件

输出说明：

- TIME：时间戳
- PID
- MSG：用户设置的输出
