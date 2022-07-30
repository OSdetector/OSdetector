import os
from utils import get_delta

probe_header = """
struct probe_data_t {
    u64 total_size;
    u64 number_of_allocs;
    u64        utime;         //用户态消耗的CPU时间
    u64        stime;         //内核态消耗的CPU时间
    unsigned long      nvcsw; //自愿(voluntary)上下文切换计数
    unsigned long      nivcsw;//非自愿(involuntary)上下文切换计数
    u64 start_time;
    u64 end_time;
    u64 cost_time;
    char event_name[30];
    u32 tgid;
};
BPF_QUEUE(probe_message_queue, struct probe_data_t, 1024);
"""

probe_prg = """
BPF_HASH(EVENT_NAME_enter_status, u32, struct probe_data_t);  // 暂存进入probe时的状态（CPU时间，内存占用）

int EVENT_NAME_uprobe(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid()>>32;
    u32 pid = bpf_get_current_pid_tgid();
    if(lookup_tgid(tgid) == 0)
        return 0;
    SPID_FILTER
    struct combined_alloc_info_t* info = combined_allocs.lookup(&tgid);
    struct combined_alloc_info_t zero_combined_alloc = {0};
    if(info==NULL)
    {
        info = &zero_combined_alloc;
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct probe_data_t data; 
    __builtin_memset(&data, 0, sizeof(data));
    data.total_size = info->total_size;
    data.number_of_allocs = info->number_of_allocs;
    data.utime = task->utime;
    data.stime = task->stime;
    data.nvcsw = task->nvcsw;
    data.nivcsw = task->nivcsw;
    data.start_time = bpf_ktime_get_ns();
    data.tgid = 0;
    __builtin_memcpy(data.event_name, "EVENT_NAME", sizeof(data.event_name));
    EVENT_NAME_enter_status.update(&tgid, &data);

    return 0;
}

int EVENT_NAME_uretprobe(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid()>>32;
    u32 pid = bpf_get_current_pid_tgid();
    if(lookup_tgid(tgid) == 0)
        return 0;
    struct combined_alloc_info_t* info = combined_allocs.lookup(&tgid);
    struct combined_alloc_info_t zero_combined_alloc = {0};
    if(info==NULL)
    {
        info = &zero_combined_alloc;
    }
    SPID_FILTER
    struct probe_data_t* prev_data_p = EVENT_NAME_enter_status.lookup(&tgid);
    u64 time = bpf_ktime_get_ns();
    if(prev_data_p!=NULL)
    {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct probe_data_t delta; 
        __builtin_memset(&delta, 0, sizeof(delta));            // 确保结构体对齐，满足对界要求
        delta.total_size = info->total_size - prev_data_p->total_size;
        delta.number_of_allocs = info->number_of_allocs - prev_data_p->number_of_allocs;
        delta.utime = task->utime - prev_data_p->utime;
        delta.stime = task->stime - prev_data_p->stime;
        delta.nvcsw = task->nvcsw - prev_data_p->nvcsw;
        delta.nivcsw = task->nivcsw - prev_data_p->nivcsw;
        delta.start_time = prev_data_p->start_time;
        delta.end_time = time;
        delta.cost_time = time - prev_data_p->start_time;
        delta.tgid = task->tgid;
        __builtin_memcpy(delta.event_name, "EVENT_NAME", sizeof(delta.event_name));
        probe_message_queue.push(&delta, BPF_EXIST);
    }

    return 0;
}
"""


def probe_print_header(output_file):
    output_file.write(
        "%s,%s,%s,%s,%s,%s,%s,%s,%s, %s, %s\n" %
        ("PID", "EVENT NAME", "SIZE", "NUM", "UTime", "STime", "NVCSW",
         "NIVCSW", "ENTER TIME", "RETURN TIME", "TOTAL TIME"))


def attach_uprobe(bpf_obj, configure):
    probes = configure["probes"]
    for probe in probes["event_name"]:
        name, sym = probe.split(":")
        bpf_obj.attach_uprobe(name=name, sym=sym, fn_name=sym + "_uprobe")
        bpf_obj.attach_uretprobe(name=name,
                                 sym=sym,
                                 fn_name=sym + "_uretprobe")

    return


def probe_generate_prg(prg, configure):
    prg += probe_header
    for event_name in configure['probes']['event_name']:
        tmp = probe_prg.replace("EVENT_NAME", event_name.split(":")[-1])
        if not configure['probes']['spid'] is None:
            tmp = tmp.replace(
                "SPID_FILTER",
                "if(pid!=%d) return 0;" % configure['probes']['spid'])
        else:
            tmp = tmp.replace("SPID_FILTER", "")
        prg += tmp
    return prg


def uprobe_record(output_file, bpf_obj):
    HZ = os.sysconf("SC_CLK_TCK")
    delta = get_delta()
    while True:
        try:
            data = bpf_obj["probe_message_queue"].pop()
            output_file.write(
                "%d, %s, %u, %u, %.2f, %.2f, %d, %d, %.2f, %.2f, %.2f\n" % (
                    data.tgid,
                    data.event_name,
                    data.total_size,
                    data.number_of_allocs,
                    #  unit: ms
                    data.utime * 1e-4 /
                    HZ,  # FIXME:Magic Num: It seems that 1 Jiffies = 1e7 * CPU_TIME
                    data.stime * 1e-4 / HZ,
                    data.nvcsw,
                    data.nivcsw,
                    data.start_time * 1e-9 + delta,
                    data.end_time * 1e-9 + delta,
                    data.cost_time * 1e-6))
        except KeyError:
            output_file.flush()
            break
