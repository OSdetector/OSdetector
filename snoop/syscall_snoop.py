#! /bin/python3
from bcc import BPF
import psutil
from utils import run_command_get_pid
text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

enum output_type{
    ENTER,
    RETURN
};

#define SYSCALL_ID_EXIT 64
#define SYSCALL_ID_EXIT_GROUP 231

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

BPF_PERF_OUTPUT(enter_channel);
BPF_PERF_OUTPUT(ret_channel);
BPF_PERF_OUTPUT(event);

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    struct data_t data = {0};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    if(data.pid != SNOOP_PID)
        return 0;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.syscall_id = args->id;
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

    bpf_trace_printk("Enter %d %u\\n", 
                        data.syscall_id,
                        data.ret);
    if(data.syscall_id==SYSCALL_ID_EXIT || data.syscall_id==SYSCALL_ID_EXIT_GROUP)
        bpf_trace_printk("END 0 0\\n");
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    struct data_t data = {0};
    data.pid = bpf_get_current_pid_tgid() >> 32;

    if(data.pid != SNOOP_PID)
        return 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
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
    
    bpf_trace_printk("Leave %d %d\\n", 
                        data.syscall_id, data.ret);
    return 0;
}
"""

class SyscallSnoop():
    def __init__(self) -> None:
        self.prg = text
    
    def generate_program(self, snoop_pid):
        self.prg = self.prg.replace("SNOOP_PID", str(snoop_pid))
        return

    def attatch_probe(self):
        self.bpf = BPF(text=self.prg)
        return  

    def record(self, task, pid, ts, msg):
        if msg is None:
            return
        msg = msg.split(b" ")
        self.output_file.write("%-18.9f,%-16s,%-6d,%s,%s,%s\n" % (ts, task, pid, msg[0], msg[1], msg[2]))
        # print(("%-18.9f, %-16s, %-6d, %s, %s, %s\n" % (ts, task, pid, msg[0], msg[1], msg[2])))
        self.output_file.flush()
        if(msg[0] == b'END'):
            self.output_file.close()
            exit()
    def main_loop(self):
        while 1:
            # print("1")
            try:
                (task, pid, cpu, flags, ts, msg) = self.bpf.trace_fields(nonblocking=False)
            except KeyboardInterrupt:
                if not self.output_file.closed:
                    self.output_file.close()
                continue
            self.record(task, pid, ts, msg)
            # try:
            #     status = self.proc.status()
            # except Exception:
            #     self.output_file.write("END")
            #     self.output_file.close()
            #     exit()
            # if status == "zombie":
            #     self.output_file.write("END")
            #     self.output_file.close()
            #     exit()

    def run(self, output_filename, snoop_pid):
        self.proc = psutil.Process(snoop_pid)
        self.generate_program(snoop_pid)
        self.attatch_probe()
        self.output_file = open(output_filename, "w")
        self.output_file.write("TICKS,COMM,PID,ACTION,SYSCALL_ID,RET\n")
        self.main_loop()


if __name__=="__main__":
    snoop = SyscallSnoop()
    pid = run_command_get_pid("../test_examples/mem")
    snoop.run(output_filename="tmp.csv", snoop_pid=pid)
