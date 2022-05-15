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

typedef struct process_info{
    u32 pid;
    char comm[TASK_COMM_LEN];
}process_info;

BPF_HASH(oncpu_start, u32, u64, MAX_PID);    // BPF_HASH(name [, key_type [, leaf_type [, size]]])
BPF_HASH(offcpu_start, u32, u64, MAX_PID);   // BPF_HASH(name [, key_type [, leaf_type [, size]]])
BPF_HASH(cpu_time, u32, process_cpu_time, MAX_PID);

/*
char* get_comm(u32 pid)
{
    FILE *fp;
    char* file_path = "/proc/";
    strcat(file_path, itoa(pid));
    strcat(file_path, "/comm");
    if((fp=fopen(file_path,"r"))==NULL){
        printf("\nCannot open file strike any key exit!");
        getch();
        exit(1);
    }
    fgets(str,TASK_COMM_LEN,fp);
    fclose(fp);
    return str
}
*/

static inline bool str_cmp(const char* str1, const char* str2, const int max_len)
{
    for(int i = 0; i < max_len; i++)
    {
        if(str1[i] != str2[i])
            return false;
        else if(str1[i] == 0 && str2[i] == 0)
            return true;
    }
    return true;
}

static inline void str_cpy(char* Dest, const char *Src)
{
     while((*Dest = *Src)!=0)
     {
         Dest++;
         Src++;
     }
}

// 记录ON-CPU的开始时间
static inline void store_oncpu_start(u32 tgid, u32 pid, u64 ts)
{
    oncpu_start.update(&pid, &ts);
}

// 记录OFF-CPU的开始时间
static inline void store_offcpu_start(u32 tgid, u32 pid, u64 ts)
{
    offcpu_start.update(&pid, &ts);
}

// 更新ON-CPU的持续时间
static inline void update_oncpu_time(u32 tgid, u32 pid, u64 ts)
{
    u64 *tsp = oncpu_start.lookup(&pid);
    if (tsp == 0)
        return;
    
    if(ts < *tsp)
        return;
    
    u64 delta = ts - *tsp;
    process_cpu_time* p = cpu_time.lookup(&pid);

    if(p != NULL)
        p->oncpu_time+=delta;
    else
    {
        process_cpu_time init = {0, 0};
        cpu_time.update(&pid, &init);
    }

    //oncpu_time.increment(pid, delta);
    //oncpu_time.update(&pid, &delta);
}

// 更新OFF-CPU的持续时间
static inline void update_offcpu_time(u32 tgid, u32 pid, u64 ts)
{
    u64 *tsp = offcpu_start.lookup(&pid);

    if (tsp == 0)
        return;
    
    if(ts < *tsp)
        return;
    
    u64 delta = ts - *tsp;
    process_cpu_time* p = cpu_time.lookup(&pid);
    if(p != NULL)
        p->offcpu_time+=delta;
    else
    {
        process_cpu_time init = {0, 0};
        cpu_time.update(&pid, &init);
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
    PREV_PID_FILTER
    {
        update_oncpu_time(prev_tgid, prev_pid, ts);
        store_offcpu_start(prev_tgid, prev_pid, ts);
    }

BAIL:
    // 记录当前进程的on-cpu开始并更新off-cpu的时长
    PID_FILTER
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
    
    def parse_args(self):
        parser = argparse.ArgumentParser(description="Attach to " +
                  "process and snoop its resource usage",
                  formatter_class=argparse.RawDescriptionHelpFormatter,
                  epilog=examples)
        parser.add_argument("-p", "--pid", type=int, metavar="PID",
            help="id of the process to trace (optional)")
        parser.add_argument("-c", "--command",
            help="execute and trace the specified command")
        parser.add_argument("-i", "--interval", type=int, 
            help="The interval of snoop")
        args = parser.parse_args()
        if args.command is not None:
            print("Executing '%s' and tracing the resulting process." % args.command)
            popen = run_command(args.command)
            self.popens.append(popen)
            self.snoop_pid = popen.pid
        else:
            self.snoop_pid = args.pid
        self.interval = args.interval if args.interval is not None else 5


    def generate_program(self, snoop_pid):
        self.prg = self.prg.replace("PREV_PID_FILTER",
                "if(prev_pid==%d)" % snoop_pid)
        self.prg = self.prg.replace("PID_FILTER", 
                "if(pid==%d)" % snoop_pid)
        return

    def attatch_probe(self):
        max_pid = int(open("/proc/sys/kernel/pid_max").read())
        self.bpf = BPF(text=self.prg, cflags=["-DMAX_PID=%d" % max_pid])
        self.bpf.attach_kprobe(event_re="^finish_task_switch$", fn_name="sched_switch")
        # self.bpf.attach_tracepoint("sys_exit_*", "clear_proc_time")

        return

    # def record(self, process_cpu_time, period, time_stamp):
    #     ######################################################################
    #     ########### 方案1：不刷新，但记录前一个周期结束时的cpu时间，再做差########
    #     ######################################################################
    #     process_cpu_util = {}
    #     for key, val in self.cpu_time.items():
    #         pid = key.value
    #         if pid == 0:
    #             continue
    #         comm = pid_to_comm(pid).strip("\n")
    #         try:
    #             on_cpu_time = float(val.oncpu_time / 1e6) - process_cpu_time[pid]['oncpu_time']
    #         except KeyError:
    #             on_cpu_time = float(val.oncpu_time / 1e6)
    #         try:
    #             off_cpu_time = float(val.offcpu_time / 1e6) - process_cpu_time[pid]['offcpu_time']
    #         except KeyError:
    #             off_cpu_time = float(val.offcpu_time / 1e6)            
    #         process_cpu_time[pid] = {'comm':comm.strip('\n'), 
    #                                 'oncpu_time':float(val.oncpu_time / 1e6), 
    #                                 'offcpu_time':float(val.offcpu_time / 1e6)
    #                                 }
    #         try:
    #             utilization = float(on_cpu_time / period)
    #         except ZeroDivisionError:
    #             utilization = 0
    #         process_cpu_util[pid] = {'comm': comm.strip('\n'),
    #                                 'oncpu_time': on_cpu_time,
    #                                 'offcpu_time': off_cpu_time,
    #                                 'total_cpu_time':on_cpu_time+off_cpu_time,
    #                                 'utilization': utilization,
    #                                 'period': period
    #         }    
    #     for k, v in sorted(process_cpu_util.items(),
    #                     key = lambda x: x[1]['utilization'],
    #                     reverse=True):
    #         self.output_file.write("%-12.2f %-12d %-20s %-20.2f %-20.2f %-20.2f\n" % (
    #                                 time_stamp,
    #                                 k, 
    #                                 v['comm'],
    #                                 v['oncpu_time'], 
    #                                 v['offcpu_time'],
    #                                 v['utilization'] * 100,
    #                                 )
    #         )

    def record(self, process_cpu_time, period, time_stamp):
        for k, v in sorted(self.bpf['cpu_time'].items_lookup_and_delete_batch(), key=lambda kv: (kv[1].oncpu_time), reverse=True):
            comm = pid_to_comm(k).strip('\n')
            oncpu_time_ms = v.oncpu_time / 1e6
            # offcpu_time_ms = v.offcpu_time / 1e6
            offcpu_time_ms = period - oncpu_time_ms
            # total_time_ms = oncpu_time_ms + offcpu_time_ms
            total_time_ms = period
            # utilization = oncpu_time_ms / total_time_ms if total_time_ms > 0 else 0
            utilization = oncpu_time_ms / total_time_ms if total_time_ms > 0.1 else 0
            # self.output_file.write("%-12.2f %-12d %-20s %-20.2f %-20.2f %-20.2f\n" % (
            #                         time_stamp,
            #                         k, 
            #                         comm,
            #                         oncpu_time_ms, 
            #                         offcpu_time_ms,
            #                         utilization * 100,
            #                         ))
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

    def main_loop(self, interval, process_cpu_time):
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
            self.record(process_cpu_time, (cur_time-prev_time)*1e3, cur_time)
            prev_time = cur_time
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
        return
    
    def run(self, interval, output_filename, snoop_pid):
        self.proc = psutil.Process(snoop_pid)
        self.generate_program(snoop_pid=snoop_pid)
        self.attatch_probe()
        self.start_time = time.time()
        self.cpu_time = self.bpf['cpu_time']
        process_cpu_time = {}

        self.output_file = open(output_filename, 'w')
        # 写表头
        # self.output_file.write("%-12s %-12s %-20s %-20s %-20s %-20s\n" 
        #                         % ("TICKS", "PID", "COMM", "ON CPU(ms)", "OFF CPU(ms)", "CPU%"))
        self.output_file.write("%12s,%12s,%20s,%20s,%20s,%20s\n" 
                                % ("TICKS", "PID", "COMM", "ON CPU(ms)", "OFF CPU(ms)", "CPU%"))
        self.main_loop(interval, process_cpu_time)

if __name__=="__main__":
    snoop = CPUSnoop()
    pid = run_command_get_pid("/home/li/repository/bcc_detector/OSdetector/test_examples/cpu")
    snoop.run(interval=1, output_filename="tmp.csv", snoop_pid=pid)

