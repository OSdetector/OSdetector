from bcc import BPF
from time import sleep
import sys
text="""
int modify_epoll_wait_retval(struct pt_regs *ctx)
{
    unsigned long rc = 0;
    u32 tgid = bpf_get_current_pid_tgid()>>32;
    if(tgid != PID)
        return 0;
    bpf_override_return(ctx, rc);
    return 0;
}
"""
pid = str(sys.argv[1])
if pid=="":
    print("Must specific at least 1 proc.\n")
    exit()
time = int(sys.argv[2])

b=BPF(text=text.replace("PID", pid))
b.attach_kprobe(event=b.get_syscall_fnname("modify_epoll_wait_retval"), fn_name="bpf_prog1")
sleep(time)