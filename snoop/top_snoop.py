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
// WARNING: 需要在当前进程的TGID就是tgid的条件下使用
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
                //bpf_trace_printk("Add new snoop proc, task_tgid=%d, tgid=%d, ppid=%d\\n", task_tgid, tgid, ppid);
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
   // bpf_trace_printk("Remove %d\\n", tgid);

    return 0;
}


"""

def main_loop(configure, output_fp, bpf_obj):
    """主循环体，定期唤醒记录各种信息

    Args:
        configure (_type_): _description_
        output_fp (DICT[name, FILE*]): _description_
        bpf_obj (_type_): _description_
    """
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
                cpu_top_record(output_file=output_fp["cpu"], cur_time=cur_time, snoop_pid=configure["snoop_pid"], show_all_threads=configure["show_all_threads"])
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
            while True:
                try:
                    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
                except ValueError:
                    break
                print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
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
    """从配置文件(.json)中读取配置

    Args:
        file_name (_type_): _description_

    Returns:
        _type_: _description_
    """
    with open(file_name) as configure_file:
            configure = json.load(configure_file)
    
    return configure

def parse_args():
        """
        处理输入参数
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
    """检查configure中的各个变量是否合法

    Args:
        configure (_type_): _description_
    """
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

        if not configure["trace_multiprocess"] in [True, False]:
            print("ERROR: Invalid value for trace_multiprocess, the value must be 'True' or 'False'!\n")
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
    """生成挂载到eBPF的程序

    Args:
        configure (_type_): _description_

    Returns:
        _type_: _description_
    """
    prg=header
    output_fp = {}
    if configure['snoop_cpu'] == "bcc":
        prg += cpu_prg
        output_fp['cpu'] = open(configure["cpu_output_file"], "w")
        cpu_bcc_print_header(output_fp['cpu'])
    elif configure["snoop_cpu"] == "stat":
        output_fp['cpu'] = open(configure["cpu_output_file"], "w")
        cpu_stat_print_header(output_fp['cpu'])
    elif configure["snoop_cpu"] == "top":
        output_fp['cpu'] = open(configure["cpu_output_file"], "w")
        cpu_top_print_header(output_fp['cpu'])
    
    if configure['snoop_mem'] == "bcc":
        prg = mem_generate_prg(prg, configure)
        output_fp['mem'] = open(configure["mem_output_file"], "w")
        mem_print_header(output_fp['mem'])
        if not configure['probes'] is None:
            prg = probe_generate_prg(prg, configure)
            output_fp["probes"] = open(configure["probes"]["output_file"], "w")
            probe_print_header(output_fp["probes"])

    if configure['snoop_network'] == "bcc":
        prg = network_generate_prg(prg, configure["show_all_threads"])
        output_fp["network"] = open(configure["network_output_file"], "w")
        network_print_header(output_fp["network"])

    if configure["snoop_syscall"] == "bcc":
        prg = syscall_generate_prg(prg, configure["show_all_threads"])
        output_fp['syscall'] = open(configure["syscall_output_file"], "w")
        syscall_print_header(output_fp['syscall'])

    if not configure["trace"] is None:
        prg = tracer_generate_prg(prg, configure)
        output_fp["trace"] = open(configure["trace"]["output_file"], "w")
        trace_print_header(output_fp["trace"])
    
    prg += additional_func
    prg = prg.replace("SNOOP_PID", str(configure['snoop_pid']))
    prg = prg.replace("MULTI_PROCESS", "true") if configure["trace_multiprocess"]==True else prg.replace("MULTI_PROCESS", "false")


    return prg, output_fp

def attach_probes(configure, bpf_obj):
    """挂载eBPF程序

    Args:
        configure (_type_): _description_
        bpf_obj (_type_): _description_
    """
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
            from cpu_snoop import cpu_prg, cpu_attach_probe, cpu_record, cpu_bcc_print_header
        elif configure["snoop_cpu"] == "stat":
            from cpu_snoop_stat import cpu_stat_record, cpu_stat_print_header
        elif configure["snoop_cpu"] == "top":
            from cpu_snoop_top import cpu_top_record, cpu_top_print_header
        if configure['snoop_mem'] == "bcc":
            from mem_snoop import mem_generate_prg, mem_attach_probe, mem_record, mem_print_header
            if not configure['probes'] is None:
                from probe import probe_generate_prg, attach_uprobe, uprobe_record, probe_print_header
        if configure['snoop_network'] == "bcc":
            from network_snoop import network_generate_prg, network_attach_probe, network_record, network_print_header
        if configure["snoop_syscall"] == "bcc":
            from syscall_snoop import syscall_generate_prg, syscall_attach_probe, syscall_record, syscall_print_header
        if not configure["trace"] is None:
            from tracer import tracer_generate_prg, trace_attach_probe, trace_record, trace_print_header
    
        proc = psutil.Process(configure['snoop_pid'])
        prg, output_fp = generate_prg(configure)
        b = BPF(text=prg)
        attach_probes(configure, b)
        main_loop(configure, output_fp, b)


