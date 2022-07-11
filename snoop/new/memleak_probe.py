import time
import os
memleak_prg = """
struct probe_data_t{
    u64 total_size;
    u64 number_of_allocs;
    u64        utime;//用户态消耗的CPU时间
    u64        stime;//内核态消耗的CPU时间
    unsigned long      nvcsw;//自愿(voluntary)上下文切换计数
    unsigned long      nivcsw;//非自愿(involuntary)上下文切换计数
    u64 time;
};

BPF_QUEUE(memleak_queue, struct combined_alloc_info_t, 10240);
BPF_QUEUE(probe_queue, struct probe_data_t, 1024);
BPF_HASH(enter_status, u32, struct probe_data_t);

int uprobe_output(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid()>>32;
    if(lookup_tgid(tgid) == 0)
        return 0;
    struct combined_alloc_info_t* info = combined_allocs.lookup(&tgid);
    struct combined_alloc_info_t zero_combined_alloc = {0};
    if(info==NULL)
    {
        info = &zero_combined_alloc;
    }
    memleak_queue.push(info, 0);
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct probe_data_t data = {
        .total_size = info->total_size,
        .number_of_allocs = info->number_of_allocs,
        .utime = task->utime,
        .stime = task->stime,
        .nvcsw = task->nvcsw,
        .nivcsw = task->nivcsw,
        .time = bpf_ktime_get_ns()
    };
    enter_status.update(&tgid, &data);

    return 0;
}

int uretprobe_output(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid()>>32;
    if(lookup_tgid(tgid) == 0)
        return 0;
    struct combined_alloc_info_t* info = combined_allocs.lookup(&tgid);
    struct combined_alloc_info_t zero_combined_alloc = {0};
    if(info==NULL)
    {
        info = &zero_combined_alloc;
    }
    memleak_queue.push(info, 0);

    struct probe_data_t* prev_data_p = enter_status.lookup(&tgid);
    if(prev_data_p!=NULL)
    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct probe_data_t data = {
            .total_size = info->total_size,
            .number_of_allocs = info->number_of_allocs,
            .utime = task->utime,
            .stime = task->stime,
            .nvcsw = task->nvcsw,
            .nivcsw = task->nivcsw,
        };
        struct probe_data_t delta = {
            .total_size = info->total_size - prev_data_p->total_size,
            .number_of_allocs = info->number_of_allocs - prev_data_p->number_of_allocs,
            .utime = task->utime - prev_data_p->utime,
            .stime = task->stime - prev_data_p->stime,
            .nvcsw = task->nvcsw - prev_data_p->nvcsw,
            .nivcsw = task->nivcsw - prev_data_p->nivcsw,
            .time = bpf_ktime_get_ns() - prev_data_p->time
        };
        probe_queue.push(&delta, 0);
    }

    return 0;
}
"""

def memleak_attach_probe(bpf_obj, configure):
    memleak_probes = configure["memleak_probes"]
    for probe in memleak_probes["probes"]:
        name, sym = probe.split(":")
        print(name, sym)
        bpf_obj.attach_uprobe(name=name, sym_re=sym, fn_name="uprobe_output")
        bpf_obj.attach_uretprobe(name=name, sym_re=sym, fn_name="uretprobe_output")
    
    return 

def memleak_record(output_file, bpf_obj):
    memleak_queue = bpf_obj["memleak_queue"]
    HZ = os.sysconf("SC_CLK_TCK")
    while True:
        try:
            # info = memleak_queue.pop()
            # ts = time.time()
            # output_file.write("%f,%d,%d\n" % (ts, info.total_size, info.number_of_allocs))

            data = bpf_obj["probe_queue"].pop()
            print("%u, %u, %.2f, %.2f, %d, %d, %.2f\n" % 
                    (data.total_size,
                     data.number_of_allocs,
                     #  unit: ms
                     data.utime * 1e-4 / HZ,       # FIXME:Magic Num: It seems that 1 Jiffies = 1e7 * CPU_TIME
                     data.stime * 1e-4 / HZ,
                     data.nvcsw,
                     data.nivcsw,
                     data.time * 1e-6))
        except KeyError:
            break
    output_file.flush()


