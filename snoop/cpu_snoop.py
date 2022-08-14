from utils import pid_to_comm
cpu_prg = """
#ifndef _CPU_SNOOP
#define _CPU_SNOOP
#endif
// 记录进程CPU时间
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

    // 因为finish_task_switch执行时task结构体已经切换为当前进程，此时无法获取前一个进程的ppid，所以只检查前一个进程本身是否在snoop_proc中
    if(snoop_proc.lookup(&prev_tgid) != NULL)    
    {
        update_oncpu_time(prev_tgid, prev_pid, ts);
        store_offcpu_start(prev_tgid, prev_pid, ts);
    }

BAIL:
    // 记录当前进程的on-cpu开始并更新off-cpu的时长
    if(lookup_tgid(tgid))
    {    
        update_offcpu_time(tgid, pid, ts);
        store_oncpu_start(tgid, pid, ts);
    }
    //bpf_trace_printk("Time clapsed: %d\\n", bpf_ktime_get_ns()-ts);

    return 0;
}

// 挂载到内核进程退出函数
static inline int clear_proc_time(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;

    oncpu_start.delete(&tgid);
    offcpu_start.delete(&tgid);
    cpu_time.delete(&tgid);

    return 0;
}
"""
def cpu_generate_prg(prg, configure):
    prg += cpu_prg
    return prg
    
def cpu_bcc_print_header(output_file):
    output_file.write("%s,%s,%s,%s,%s,%s\n" %("TIME", "PID", "COMM", "ON CPU", "OFF CPU", "CPU%"))


def cpu_attach_probe(bpf_obj):
        bpf_obj.attach_kprobe(event_re="^finish_task_switch$", fn_name="sched_switch")
        # bpf_obj.attach_tracepoint("sys_exit_*", "clear_proc_time")

def cpu_record(output_file, period, time_stamp, bpf_obj):
    for k, v in sorted(bpf_obj['cpu_time'].items_lookup_and_delete_batch(), key=lambda kv: (kv[0]), reverse=False):
        comm = pid_to_comm(k).strip('\n')
        oncpu_time_ms = v.oncpu_time / 1e6   # eBPF虚拟机以ns为单位记录
        offcpu_time_ms = period - oncpu_time_ms
        total_time_ms = period
        utilization = oncpu_time_ms / total_time_ms if total_time_ms > 0.1 else 0
        output_file.write("%.2f,%12d,%20s,%.2f,%.2f,%.2f\n" % (
                                time_stamp,
                                k, 
                                comm,
                                oncpu_time_ms, 
                                offcpu_time_ms,
                                utilization * 100,
                                )
        )
    output_file.flush()