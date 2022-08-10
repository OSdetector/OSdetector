from collections import namedtuple, defaultdict

from utils import pid_to_comm

network_prg = """
#ifndef _NETWORK_SNOOP
#define _NETWORK_SNOOP
#endif
struct throughput_key_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};

BPF_HASH(send_bytes, struct throughput_key_t);
BPF_HASH(recv_bytes, struct throughput_key_t);

// 挂载到ip向数据链路层传送数据包处
TRACEPOINT_PROBE(net, net_dev_queue)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    // 检查是否为监控进程
    if(lookup_tgid(tgid) == 0)
            return 0;
    struct throughput_key_t throughput_key = {.pid = tgid};
    bpf_get_current_comm(&throughput_key.name, sizeof(throughput_key.name));

    send_bytes.increment(throughput_key, args->len);
    
    return 0;
}
// 挂载到接收函数
TRACEPOINT_PROBE(net, netif_receive_skb)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    // 检查是否为监控进程
    if(lookup_tgid(tgid) == 0)
            return 0;
    struct throughput_key_t throughput_key = {.pid = tgid};
    bpf_get_current_comm(&throughput_key.name, sizeof(throughput_key.name));

    recv_bytes.increment(throughput_key, args->len);

    return 0;
}

static inline int clear_throughput(struct pt_regs *ctx)
{
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 tgid = pid_tgid >> 32, pid = pid_tgid;

        struct throughput_key_t throughput_key = {.pid = tgid};
        bpf_get_current_comm(&throughput_key.name, sizeof(throughput_key.name));

        send_bytes.delete(&throughput_key);
        recv_bytes.delete(&throughput_key);


    return 0;
}
"""
def network_attach_probe(bpf_obj):
    pass

def network_print_header(output_file):
    output_file.write("%s,%s,%s,%s,%s\n" % ("TIME", "PID", "COMM", "RX_KB", "TX_KB"))

def network_generate_prg(prg, show_all_threads=False):
    if show_all_threads == True:
        prg += network_prg.replace("PID", "pid")
    else:
        prg+= network_prg.replace("PID", "tgid")
    return prg

def network_record(output_file, cur_time, bpf_obj):
    ThroughputKey = namedtuple('Throughput', ['pid', 'name'])
    def get_throughput_key(k):
        return ThroughputKey(pid=k.pid, name=k.name)
    throughput = defaultdict(lambda: [0, 0])
    for k, v in bpf_obj['recv_bytes'].items():
        key = get_throughput_key(k)
        throughput[key][0] = v.value
    bpf_obj['recv_bytes'].clear()
    for k, v in bpf_obj['send_bytes'].items():
        key = get_throughput_key(k)
        throughput[key][1] = v.value
    bpf_obj['send_bytes'].clear()
    valid = 0
    # output
    for k, (send_bytes, recv_bytes) in sorted(throughput.items(),
                                            key=lambda kv: sum(kv[1]),
                                            reverse=True):
        output_file.write("%.2f,%d,%.12s,%.2f,%.2f\n" % (cur_time,
                                                        k.pid,
                                                        k.name,
                                                        (recv_bytes / 1024), (send_bytes / 1024)))
        valid = 1
    if valid == 0:
        for key in bpf_obj['snoop_proc'].keys():
            output_file.write("%.2f,%d,%.12s,%.2f,%.2f\n" % (cur_time,
                                                            key.value,
                                                            pid_to_comm(key.value),
                                                            0.0, 0.0))
    output_file.flush()