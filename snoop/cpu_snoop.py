#! /bin/python3
from __future__ import print_function
import psutil
from utils import pid_to_comm, run_command_get_pid, run_command
from ctypes import c_uint
import os
from os import times
from bcc import BPF
from time import sleep, strftime, time
import argparse
from collections import namedtuple, defaultdict
import subprocess
import time

text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

typedef struct process_cpu_time{
    u64 oncpu_time;
    u64 offcpu_time;
}process_cpu_time;


BPF_HASH(oncpu_start, u32, u64);    // BPF_HASH(name [, key_type [, leaf_type [, size]]])
BPF_HASH(offcpu_start, u32, u64);   // BPF_HASH(name [, key_type [, leaf_type [, size]]])
BPF_HASH(cpu_time, u32, process_cpu_time);

// 记录ON-CPU的开始时间
static inline void store_oncpu_start(u32 tgid, u32 pid, u64 ts)
{
    // oncpu_start.update(&pid, &ts);
    oncpu_start.update(&tgid, &ts);
}

// 记录OFF-CPU的开始时间
static inline void store_offcpu_start(u32 tgid, u32 pid, u64 ts)
{
    //offcpu_start.update(&pid, &ts);
    offcpu_start.update(&tgid, &ts);
}

// 更新ON-CPU的持续时间
static inline void update_oncpu_time(u32 tgid, u32 pid, u64 ts)
{
    //u64 *tsp = oncpu_start.lookup(&pid);
    u64 *tsp = oncpu_start.lookup(&tgid);
    if (tsp == 0)
        return;
    
    if(ts < *tsp)
        return;
    
    u64 delta = ts - *tsp;
    //process_cpu_time* p = cpu_time.lookup(&pid);
    process_cpu_time* p = cpu_time.lookup(&tgid);

    if(p != NULL)
        p->oncpu_time+=delta;
    else
    {
        process_cpu_time init = {0, 0};
        //cpu_time.update(&pid, &init);
        cpu_time.update(&tgid, &init); 
    }
}

// 更新OFF-CPU的持续时间
static inline void update_offcpu_time(u32 tgid, u32 pid, u64 ts)
{
    //u64 *tsp = offcpu_start.lookup(&pid);
    u64 *tsp = offcpu_start.lookup(&tgid);

    if (tsp == 0)
        return;
    
    if(ts < *tsp)
        return;
    
    u64 delta = ts - *tsp;
    //process_cpu_time* p = cpu_time.lookup(&pid);
    process_cpu_time* p = cpu_time.lookup(&tgid);
    if(p != NULL)
        p->offcpu_time+=delta;
    else
    {
        process_cpu_time init = {0, 0};
        //cpu_time.update(&pid, &init);
        cpu_time.update(&tgid, &init);
    }
    //offcpu_time.increment(pid, delta);
    //offcpu_time.update(&pid, &delta);
}

// 挂载到内核函数的具体事件
int sched_switch(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;

    u32 prev_pid = prev->pid;
    u32 prev_tgid = prev->tgid;

    
    //更新之前进程的on-cpu时长并记录off-cpu的开始
    //PREV_PID_FILTER
    PREV_TGID_FILTER    // 增加对多线程程序的支持
    {
        update_oncpu_time(prev_tgid, prev_pid, ts);
        store_offcpu_start(prev_tgid, prev_pid, ts);
    }

BAIL:
    // 记录当前进程的on-cpu开始并更新off-cpu的时长
    //PID_FILTER
    TGID_FILTER          // 增加对多线程程序的支持
    {    
        update_offcpu_time(tgid, pid, ts);
        store_oncpu_start(tgid, pid, ts);
    }

    return 0;
}

// 挂载到内核进程退出函数
int clear_proc_time(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;

    oncpu_start.delete(&pid);
    offcpu_start.delete(&pid);
    cpu_time.delete(&pid);

    return 0;
}
"""

class CPUSnoop:
    def __init__(self) -> None:
        self.prg = text

    def generate_program(self, snoop_pid):
        """生成挂在程序，主要是替换监控的PID

        Args:
            snoop_pid (int): 监控进程的PID
        """
        self.prg = self.prg.replace("PREV_PID_FILTER",
                "if(prev_pid==%d)" % snoop_pid)
        self.prg = self.prg.replace("PID_FILTER", 
                "if(pid==%d)" % snoop_pid)
        self.prg = self.prg.replace("PREV_TGID_FILTER",
                "if(prev_tgid==%d)" % snoop_pid)
        self.prg = self.prg.replace("TGID_FILTER", 
                "if(tgid==%d)" % snoop_pid)
        return

    def attatch_probe(self):
        """将程序挂载到挂载点上
        """
        max_pid = int(open("/proc/sys/kernel/pid_max").read())
        self.bpf = BPF(text=self.prg, cflags=["-DMAX_PID=%d" % max_pid])
        self.bpf.attach_kprobe(event_re="^finish_task_switch$", fn_name="sched_switch")
        # self.bpf.attach_tracepoint("sys_exit_*", "clear_proc_time")

        return

    def record(self, period, time_stamp):
        """记录函数，将数据记录并输出

        Args:
            period (float): 两次调用record之间的时间间隔
            time_stamp (float): 当前时间时间戳
        """
        for k, v in sorted(self.bpf['cpu_time'].items_lookup_and_delete_batch(), key=lambda kv: (kv[1].oncpu_time), reverse=True):
            comm = pid_to_comm(k).strip('\n')
            oncpu_time_ms = v.oncpu_time / 1e6   # eBPF虚拟机以ns为单位记录
            offcpu_time_ms = period - oncpu_time_ms
            total_time_ms = period
            utilization = oncpu_time_ms / total_time_ms if total_time_ms > 0.1 else 0
            self.output_file.write("%.2f,%12d,%20s,%.2f,%.2f,%.2f\n" % (
                                    time_stamp,
                                    k, 
                                    comm,
                                    oncpu_time_ms, 
                                    offcpu_time_ms,
                                    utilization * 100,
                                    )
            )
            self.output_file.flush()

    def main_loop(self, interval):
        """
        主循环体，持续等待eBPF虚拟机传来消息，调用
        record进行输出
        """
        prev_time = self.start_time
        while True:
            try:
                sleep(interval)
            except KeyboardInterrupt:
                print("receive KeyBoardInterrupt")
                if not self.output_file.closed:
                    self.output_file.flush()
                    self.output_file.close()
                exit()  
            cur_time = time.time()
            self.record((cur_time-prev_time)*1e3, cur_time)
            prev_time = cur_time
            # 判断监控进程的状态，如果监控进程编程僵尸进程或进程已退出，则结束监控
            try:
                status = self.proc.status()
            except Exception:
                self.output_file.write("END")
                self.output_file.close()
                exit()
            if status == "zombie":
                self.output_file.write("END")
                self.output_file.close()
                exit()
    
    def run(self, interval, output_filename, snoop_pid):
        """运行方法，对外接口
        完成挂载程序生成，挂载程序，启动主循环等功能

        Args:
            output_filename (str): 输出文件名
            snoop_pid (int): 监控进程
        """
        self.proc = psutil.Process(snoop_pid)
        self.generate_program(snoop_pid=snoop_pid)
        self.attatch_probe()
        self.start_time = time.time()
        self.cpu_time = self.bpf['cpu_time']

        self.output_file = open(output_filename, 'w')
        # 写表头
        self.output_file.write("%12s,%12s,%20s,%20s,%20s,%20s\n" 
                                % ("TICKS", "PID", "COMM", "ON CPU(ms)", "OFF CPU(ms)", "CPU%"))
        self.main_loop(interval)

if __name__=="__main__":
    snoop = CPUSnoop()
    pid = run_command_get_pid("/home/li/repository/bcc_detector/OSdetector/test_examples/cpu")
    snoop.run(interval=20, output_filename="tmp.csv", snoop_pid=pid)