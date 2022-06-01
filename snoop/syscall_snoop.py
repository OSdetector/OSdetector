#! /bin/python3
from bcc import BPF
import psutil
from utils import run_command_get_pid
text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// 向前端携带信息，表示本次输出是进程进入或退出某个系统调用
enum output_type{
    ENTER,
    RETURN
};
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
// 这种输出方式会有乱序问题，暂时不采用
//BPF_PERF_OUTPUT(enter_channel);
//BPF_PERF_OUTPUT(ret_channel);
//BPF_PERF_OUTPUT(event);

// 挂载到系统调用统一入口处
TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    struct data_t data = {0};

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tgid = bpf_get_current_pid_tgid();

    PID_FILTER
    TGID_FILTER

    data.pid = pid;
    data.ts = bpf_ktime_get_ns();
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
    bpf_trace_printk("Enter %d %u\\n", 
                        data.syscall_id,
                        data.ret);
    
    // 因为乱序问题弃用
    // enter_channel.perf_submit(args, &data, sizeof(data));
    //event.perf_submit(args, &data, sizeof(data));

    return 0;
}

// 挂载到系统调用统一返回处
TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    struct data_t data = {0};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tgid = bpf_get_current_pid_tgid();

    PID_FILTER
    TGID_FILTER

    data.pid = pid;
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
    bpf_trace_printk("Leave %d %d\\n", 
                        data.syscall_id, data.ret);
    // 因为乱序问题弃用
    //ret_channel.perf_submit(args, &data, sizeof(data));
    //event.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

class SyscallSnoop():
    def __init__(self) -> None:
        self.prg = text
    
    def generate_program(self, snoop_pid, snoop_one_thread=False):
        """生成挂在程序，主要是替换监控的PID

        Args:
            snoop_pid (int): 监控进程的PID
        """

        if snoop_one_thread==True:
            self.prg = self.prg.replace("PID_FILTER", "if(pid==%d) return 0;" % snoop_pid)
            self.prg = self.prg.replace("TGID_FILTER", "")
        else:
            self.prg = self.prg.replace("TGID_FILTER", "if(tgid==%d) return 0;" % snoop_pid)
            self.prg = self.prg.replace("PID_FILTER", "")
        return

    def attatch_probe(self):
        """将程序挂载到挂载点上
        """
        self.bpf = BPF(text=self.prg)
        return  

    def record(self, task, pid, ts, msg):
        """记录函数，将数据输出到文件

        Args:
            task (str): 启动进程的命令
            pid (int): 监控进程号
            ts (int): 当前时间
            msg (str): eBPF虚拟机向前端输出的信息
        """
        if msg is None:
            return
        # 将以空格划分的信息拆分成项
        msg = msg.split(b" ")
        self.output_file.write("%-18.9f,%-16s,%-6d,%s,%s,%s\n" % (ts, task, pid, msg[0], msg[1], msg[2]))
        # print(("%-18.9f, %-16s, %-6d, %s, %s, %s\n" % (ts, task, pid, msg[0], msg[1], msg[2])))
        self.output_file.flush()
        # 输出信息为END表示监控进程已退出
        if(msg[0] == b'END'):
            self.output_file.close()
            exit()
    def main_loop(self):
        """
        主循环体，持续等待eBPF虚拟机传来消息，调用
        record进行输出
        """
        while 1:
            try:
                (task, pid, cpu, flags, ts, msg) = self.bpf.trace_fields(nonblocking=False)
            except KeyboardInterrupt:
                if not self.output_file.closed:
                    self.output_file.close()
                exit()
            self.record(task, pid, ts, msg)

    def run(self, output_filename, snoop_pid):
        """运行方法，对外接口
        完成挂载程序生成，挂载程序，启动主循环等功能

        Args:
            output_filename (str): 输出文件名
            snoop_pid (int): 监控进程
        """
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
