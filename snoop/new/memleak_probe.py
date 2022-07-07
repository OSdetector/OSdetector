import time
memleak_prg = """
BPF_QUEUE(memleak_queue, struct combined_alloc_info_t, 10240);

int uprobe_output(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid()>>32;
    struct combined_alloc_info_t* info = combined_allocs.lookup(&tgid);
    if(info==NULL)
        return 0;
    memleak_queue.push(info, 0);

    return 0;
}

int uretprobe_output(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid()>>32;
    struct combined_alloc_info_t* info = combined_allocs.lookup(&tgid);
    if(info==NULL)
        return 0;
    memleak_queue.push(info, 0);

    return 0;
}
"""

def memleak_attach_probe(bpf_obj, configure):
    memleak_probes = configure["memleak_probes"]
    for probe in memleak_probes["probes"]:
        name, sym = probe.split(":")
        bpf_obj.attach_uprobe(name=name, sym_re=sym, fn_name="uprobe_output")
        bpf_obj.attach_uretprobe(name=name, sym_re=sym, fn_name="uretprobe_output")
    
    return 

def memleak_record(output_file, bpf_obj):
    memleak_queue = bpf_obj["memleak_queue"]
    while True:
        try:
            info = memleak_queue.pop()
            ts = time.time()
            output_file.write("%f,%d,%d\n" % (ts, info.total_size, info.number_of_allocs))
        except KeyError:
            break
    output_file.flush()


