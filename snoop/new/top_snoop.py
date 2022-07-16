#! /bin/python3
from utils import run_command_get_pid
from bcc import BPF
import time
import psutil
import argparse
import json
import os
import ctypes

examples="""
EXAMPLES:
    ./top_snoop -c './snoop_program' # Run the program snoop_program and snoop its resource usage
    ./top_snoop -p 12345  # Snoop the process with pid 12345
    ./top_snoop -p 12345 -i 1  # Snoop the process with pid 12345 and output every 1 second
"""

header = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>


BPF_HASH(snoop_proc, u32, u8);     // tgid->TRUE/FALSE

static inline int lookup_tgid(u32 tgid);
int clear_proc(struct pt_regs *ctx);
"""

additional_func = """
// 检查tgid是否是监控进程
// (1) 检查tgid是否在snoop_proc中
// (2) 检查tgid是否是snoop_proc的子进程
// WARNING: 只能检查当前进程的父进程是否是监控进程，只提供tgid无法直接获得父进程的tgid！
static inline int lookup_tgid(u32 tgid)
{
     if(snoop_proc.lookup(&tgid) != NULL)
     {
        return 1;
     }
     if(MULTI_PROCESS==true)
     {
        u8 TRUE = 1;
        struct task_struct * task = (struct task_struct *)bpf_get_current_task();
        u32 ppid = task->real_parent->tgid;
        u32 task_tgid = task->tgid;
        if(snoop_proc.lookup(&ppid) != NULL)
        {
                snoop_proc.insert(&tgid, &TRUE);
                bpf_trace_printk("Add new snoop proc, task_tgid=%d, tgid=%d, ppid=%d\\n", task_tgid, tgid, ppid);
                return 1;
        }
     }
     return 0;
}

int clear_proc(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    //bpf_trace_printk("Call clear proc tgid:%d\\n", tgid);
    if(lookup_tgid(tgid) == 0)
        return 0;

#ifdef _CPU_SNOOP
    clear_proc_time(ctx);
#endif
#ifdef _MEM_SNOOP
    clear_mem(ctx);
#endif
#ifdef _NETWORK_SNOOP
    clear_throughput(ctx);
#endif
    snoop_proc.delete(&tgid);
    bpf_trace_printk("Remove %d\\n", tgid);

    return 0;
}


"""

def main_loop(configure, output_fp, bpf_obj):
        prev_time=time.time()
        usage = None
        while True:
                try:
                        time.sleep(configure['interval'])
                except KeyboardInterrupt:
                        print("receive KeyBoardInterrupt")
                        for f in output_fp.values():
                            if not f.closed:
                                f.flush()
                                f.close()
                        exit()  
                cur_time = time.time()
                if configure["snoop_cpu"] == "bcc":
                    cpu_record(output_fp['cpu'],(cur_time-prev_time)*1e3, cur_time, bpf_obj)
                elif configure["snoop_cpu"] == "stat":
                    usage = cpu_stat_record(output_fp['cpu'], cur_time, cur_time-prev_time, configure["snoop_pid"], usage)
                elif configure["snoop_cpu"] == "top":
                    cpu_top_record(output_file=output_fp["cpu"], cur_time=cur_time, snoop_pid=configure["snoop_pid"])
                if configure["snoop_mem"] == "bcc":
                    mem_record(output_fp["mem"], cur_time, bpf_obj)
                    if not configure['probes'] is None:
                        uprobe_record(output_fp["probes"], bpf_obj)
                if configure["snoop_network"] == "bcc":
                    network_record(output_fp["network"], cur_time, bpf_obj)
                if configure["snoop_syscall"] == "bcc":
                    syscall_record(output_fp["syscall"], bpf_obj)
                if not configure["trace"] is None:
                    trace_record(output_fp["trace"], bpf_obj, configure)
                prev_time = cur_time
                # 判断监控进程的状态，如果监控进程编程僵尸进程或进程已退出，则结束监控
                try:
                        status = proc.status()
                except Exception:
                        for f in output_fp.values():
                            if not f.closed:
                                f.write("END")
                                f.flush()
                                f.close()
                        exit()
                if status == "zombie":
                        for f in output_fp.values():
                            if not f.closed:
                                f.write("END")
                                f.flush()
                                f.close()
                        exit()

def read_configure(file_name):
        with open(file_name) as configure_file:
                configure = json.load(configure_file)
        
        return configure

def parse_args():
        """处理输入参数
        """
        configure = {}
        parser = argparse.ArgumentParser(description="Attach to " +
                  "process and snoop its resource usage",
                  formatter_class=argparse.RawDescriptionHelpFormatter,
                  epilog=examples)
        parser.add_argument("-p", "--pid", type=int, metavar="PID",
            help="id of the process to trace (optional)")
        parser.add_argument("-c", "--command",
            help="execute and trace the specified command (optional)")
        parser.add_argument("-i", "--interval", type=int, default=3,
            help="The interval of snoop (unit:s)")
        parser.add_argument("--configure_file", help="File name of the configure.")
        args = parser.parse_args()
        if args.configure_file is not None:
            configure = read_configure(args.configure_file)
        # default path
        elif os.path.exists("./config.json"):
            configure = read_configure("./config.json")
        else:
            print("Please specify the configure file.")
            exit()

        configure['interval'] = args.interval if configure['interval'] is None else configure['interval']
        if args.command is not None:
            print("Executing '%s' and snooping the resulting process." % args.command)
            pid = run_command_get_pid(args.command)
            configure['snoop_pid'] = pid
        elif args.pid is not None:
            configure['snoop_pid'] = args.pid
        else:
            print("Please specify the pid or command!")
            exit()
            
        check_configure(configure)

        return configure

def check_configure(configure):
    snoop_cpu_options = ["bcc", "stat", "top"]
    try:
        if configure["snoop_cpu"] in snoop_cpu_options:
            if configure["cpu_output_file"] is None:
                print("ERROR: You must specific the output file for cpu snoop!\n")
                exit()
        elif configure["snoop_cpu"] is None:
            if not configure["cpu_output_file"] is None:
                print("WARNING: The output file for cpu snoop will be invalid since you didn't specific the cpu_snoop option!\n")
        else:
            print("ERROR: Invalid option for cpu_snoop, please check your configure file!\n")
            exit()
        
        if configure["snoop_mem"] == "bcc":
            if configure["mem_output_file"] is None:
                print("ERROR: You must specific the output file for mem snoop!\n")
                exit()
        elif configure["snoop_mem"] is None:
            if not configure["mem_output_file"] is None:
                print("WARNING: The output file for mem snoop will be invalid since you didn't specific the mem_snoop option!\n")
        else:
            print("ERROR: Invalid option for mem_snoop, please check your configure file!\n")
            exit()

        if not configure["probes"] is None:
            if not configure["snoop_mem"] == "bcc":
                print("ERROR: You must set mem_snoop to 'bcc' to run memleak_probes!\n")
                exit()
            else:
                if configure["probes"]["output_file"] is None:
                    print("ERROR: You must specific the output file for memleak probes!\n")
                    exit()

        if configure["snoop_network"] == "bcc":
            if configure["network_output_file"] is None:
                print("ERROR: You must specific the output file for network snoop!\n")
                exit()
        elif configure["snoop_network"] is None:
            if not configure["network_output_file"] is None:
                print("WARNING: The output file for network snoop will be invalid since you didn't specific the network_snoop option!\n")
        else:
            print("ERROR: Invalid option for network_snoop, please check your configure file!\n")
            exit()

        if configure["snoop_syscall"] == "bcc":
            if configure["syscall_output_file"] is None:
                print("ERROR: You must specific the output file for syscall snoop!\n")
                exit()
        elif configure["snoop_syscall"] is None:
            if not configure["syscall_output_file"] is None:
                print("WARNING: The output file for syscall snoop will be invalid since you didn't specific the syscall_snoop option!\n")
        else:
            print("ERROR: Invalid option for syscall_snoop, please check your configure file!\n")
            exit()

        if not isinstance(configure["interval"], int) and not isinstance(configure["interval"], float):
            print("ERROR: Invalid value for interval, the value must be a number!\n")
            exit()

        if not configure["trace_multiprocess"] in ["true", "false"]:
            print("ERROR: Invalid value for trace_multiprocess, the value must be 'true' or 'false'!\n")
            exit()
    except KeyError as e:
        print("ERROR: Missing required option %s in configure file!\n" % e)
        exit()

    print_configure(configure)
    
    return
        


def print_configure(configure):
        print("================================================================================")
        print("INTERVAL:", configure['interval'])
        print("SNOOP PID:", configure['snoop_pid'])
        print("Trace Multi Process:", configure["trace_multiprocess"])
        print("CPU SNOOP:")
        print("\t[%s] BCC" % ("X" if configure["snoop_cpu"]=="bcc" else " "))
        print("\t[%s] stat" % ("X" if configure["snoop_cpu"]=="stat" else " "))
        print("\t[%s] top" % ("X" if configure["snoop_cpu"]=="top" else " "))
        print("MEM SNOOP:")
        print("\t[%s] BCC" % (("X" if configure["snoop_mem"]=="bcc" else " ")))
        print("NETWORK SNOOP:")
        print("\t[%s] BCC" % ("X" if configure["snoop_network"]=="bcc" else " "))
        print("SYSCALL SNOOP:")
        print("\t[%s] BCC" % ("X" if configure["snoop_syscall"]=="bcc" else " "))
        print("================================================================================")

def generate_prg(configure):
    prg=header
    output_fp = {}
    if configure['snoop_cpu'] == "bcc":
        prg += cpu_prg
        output_fp['cpu'] = open(configure["cpu_output_file"], "w")
    elif configure["snoop_cpu"] == "stat":
        output_fp['cpu'] = open(configure["cpu_output_file"], "w")
    elif configure["snoop_cpu"] == "top":
        output_fp['cpu'] = open(configure["cpu_output_file"], "w")
    
    if configure['snoop_mem'] == "bcc":
        prg += mem_prg
        output_fp['mem'] = open(configure["mem_output_file"], "w")
        if not configure['probes'] is None:
            prg += probe_header 
            for event_name in configure['probes']['event_name']:
                prg += probe_prg.replace("EVENT_NAME", event_name.split(":")[-1])
            output_fp["probes"] = open(configure["probes"]["output_file"], "w")
    
    if configure['snoop_network'] == "bcc":
        prg += network_prg
        output_fp["network"] = open(configure["network_output_file"], "w")
    
    if configure["snoop_syscall"] == "bcc":
        prg += syscall_prg
        output_fp['syscall'] = open(configure["syscall_output_file"], "w")
    
    if not configure["trace"] is None:
        prg = tracer_generate_prg(prg, configure)
        output_fp["trace"] = open(configure["trace"]["output_file"], "w")

    
    prg += additional_func
    prg = prg.replace("SNOOP_PID", str(configure['snoop_pid']))
    prg = prg.replace("MULTI_PROCESS", str(configure["trace_multiprocess"]))


    return prg, output_fp

def attach_probes(configure, bpf_obj):
    if configure['snoop_cpu'] == "bcc":
        cpu_attach_probe(bpf_obj)
    if configure["snoop_mem"] == "bcc":
        mem_attach_probe(bpf_obj)
        if not configure['probes'] is None:
            attach_uprobe(bpf_obj, configure)
    if configure["snoop_network"] == "bcc":
        network_attach_probe(bpf_obj)
    if configure["snoop_syscall"] == "bcc":
        syscall_attach_probe()
    if not configure['trace'] is None:
        trace_attach_probe(bpf_obj, configure)

    bpf_obj.attach_tracepoint(tp_re="sched:sched_process_exit", fn_name="clear_proc")

    # 更新最早的监控进程
    b['snoop_proc'].update([(ctypes.c_uint(configure['snoop_pid']), ctypes.c_ubyte(1))])




if __name__=='__main__':
        configure = parse_args()
        if configure['snoop_cpu'] == "bcc":
            from cpu_snoop import cpu_prg, cpu_attach_probe, cpu_record
        elif configure["snoop_cpu"] == "stat":
            from cpu_snoop_stat import cpu_stat_record
        elif configure["snoop_cpu"] == "top":
            from cpu_snoop_top import cpu_top_record
        if configure['snoop_mem'] == "bcc":
            from mem_snoop import mem_prg, mem_attach_probe, mem_record
            if not configure['probes'] is None:
                from probe import probe_header, probe_prg, attach_uprobe, uprobe_record
        if configure['snoop_network'] == "bcc":
            from network_snoop import network_prg, network_attach_probe, network_record
        if configure["snoop_syscall"] == "bcc":
            from syscall_snoop import syscall_prg, syscall_attach_probe, syscall_record
        if not configure["trace"] is None:
            from tracer import tracer_generate_prg, trace_attach_probe, trace_record
    
        proc = psutil.Process(configure['snoop_pid'])
        prg, output_fp = generate_prg(configure)
        b = BPF(text=prg)
        attach_probes(configure, b)
        main_loop(configure, output_fp, b)


