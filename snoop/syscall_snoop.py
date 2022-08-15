import time
syscall_prg="""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// 向前端携带信息，表示本次输出是进程进入或退出某个系统调用
enum output_type{
    ENTER,
    RETURN
};

/*static unsigned long get_nsecs(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}*/

// 挂载函数被唤醒时可获得的数据
struct data_t{
    enum output_type type;
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    int syscall_id;
    unsigned long parm1;
    unsigned long parm2;
    unsigned long parm3;
    unsigned long parm4;
    unsigned long parm5;
    unsigned long ret;
    unsigned long fp;
    unsigned long rc;
    unsigned long sp;
    unsigned long ip;
};

BPF_QUEUE(message_queue, struct data_t, 10240);



// 挂载到系统调用统一入口处
TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    struct data_t data = {0};

    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if(lookup_tgid(tgid) == 0)
        return 0;

    data.pid = PID;
    data.ts = bpf_ktime_get_ns();
    //data.ts = get_nsecs();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.syscall_id = args->id;
    // 通过寄存器的值获取本次系统调用的参数
    struct pt_regs *regs = (struct pt_regs *)args->args;
    data.parm1 = regs->di;
    data.parm2 = regs->si;
    data.parm3 = regs->dx;
    data.parm4 = regs->cx;
    data.parm5 = regs->r8;
    data.ret = regs->sp;
    data.fp = regs->bp;
    data.rc = regs->ax;
    data.sp = regs->sp;
    data.ip = regs->ip;
    data.type = ENTER;

    // 向前端输出相关信息
    message_queue.push(&data, BPF_EXIST);
    

    return 0;
}

// 挂载到系统调用统一返回处
TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    struct data_t data = {0};
    u32 pid = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid()>>32;

    if(lookup_tgid(tgid) == 0)
        return 0;

    data.pid = PID;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));     // bpf_get_current_pid_tgid返回值为u64：pid+tgid
    data.ts = bpf_ktime_get_ns();
    data.syscall_id = args->id;
    data.parm1 = 0;
    data.parm2 = 0;
    data.parm3 = 0;
    data.parm4 = 0;
    data.parm5 = 0;
    data.fp = 0;
    data.rc = 0;
    data.sp = 0;
    data.ip = 0;
    data.ret = args->ret;
    data.type = RETURN;
    
    // 向前端输出
    message_queue.push(&data, BPF_EXIST);

    return 0;
}
"""

def syscall_attach_probe():
    pass

def syscall_generate_prg(prg, show_all_threads=False):
    prg += syscall_prg.replace("PID", "pid") if show_all_threads else syscall_prg.replace("PID", "tgid")
    return prg

def syscall_print_header(output_file):
    output_file.write("%s,%s,%s,%s,%s,%s\n" % ("TIME", "PID", "COMM", "ACTION", "SYSCALL ID", "PARM1"))

def syscall_record(output_file, bpf_obj):
    message_queue = bpf_obj['message_queue']
    with open("/proc/uptime", "r") as f:
        uptime = float(f.readline().split(" ")[0])
    delta = time.time() - uptime   # delta是uptime和unix epoch time的差值，因为ebpf虚拟机只能获取uptime所以在前端重新转换为unix epoch time
    while True:
        try:
            info = message_queue.pop()
            # print(type(info.type), type(info.comm))
            ts = info.ts*1e-9+delta
            output_file.write("%f,%16s,%-6d,%d,%d,%d\n" % (ts, info.comm, info.pid, info.type, info.syscall_id, info.parm1 if info.type==1 else info.ret))
        except KeyError:
            break
    output_file.flush()
