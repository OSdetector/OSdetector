#! /bin/python3
from bcc import BPF
import time
import psutil
from utils import run_command_get_pid

text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>


// 记录单次内存分配的数据结构
struct alloc_info_t {
        u64 size;
        u64 timestamp_ns;
        int stack_id;
};
// 记录进程所有内存分配的数据结构
struct combined_alloc_info_t {
        u64 total_size;
        u64 number_of_allocs;
};

BPF_HASH(sizes, u64);    // sizes记录某次某个pid分配的内存大小，方便在调用返回后重新获得申请的内存大小
BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);   // 记录每次分配的信息，addr->info
BPF_HASH(memptrs, u64, u64);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_HASH(combined_allocs, u32, struct combined_alloc_info_t, 10240);
BPF_HASH(snoop_proc, u32, u8);

// 更新某个进程栈的空间大小
static inline void update_statistics_add(u32 pid, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&pid);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        cinfo.total_size += sz;
        cinfo.number_of_allocs += 1;

        combined_allocs.update(&pid, &cinfo);
}
// 减小栈大小，与上面相反
static inline void update_statistics_del(u32 pid, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&pid);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        if (sz >= cinfo.total_size)
                cinfo.total_size = 0;
        else
                cinfo.total_size -= sz;

        if (cinfo.number_of_allocs > 0)
                cinfo.number_of_allocs -= 1;

        combined_allocs.update(&pid, &cinfo);
}

static inline int lookup_tgid(u32 tgid)
{
     if(snoop_proc.lookup(&tgid) != NULL)
        return 1;
     u8 TRUE = 1;
     struct task_struct * task = (struct task_struct *)bpf_get_current_task();
     u32 ppid = task->real_parent->tgid;
     u32 task_tgid = task->tgid;
     if(snoop_proc.lookup(&ppid) != NULL)
     {
        snoop_proc.insert(&tgid, &TRUE);
        bpf_trace_printk("Add new snoop proc, task_tgid=%d, tgid=%d, ppid=%d\\n", task_tgid, tgid, ppid);
        return 1;
     }
     return 0;
}

// 内存申请挂载函数，挂载在函数入口获得内存申请大小
static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
        u64 pid = bpf_get_current_pid_tgid();
        u64 size64 = size;
        sizes.update(&pid, &size64);
        return 0;
}
// 内存申请挂载函数，挂载在函数返回处更新内存信息
static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64* size64 = sizes.lookup(&pid_tgid);
        struct alloc_info_t info = {0};

        if (size64 == 0)
                return 0; // missed alloc entry
        u32 tgid = pid_tgid>>32;
        // 检查是否为监控进程
        u32 origin_tgid = SNOOP_PID;
        u8 TRUE = 1;
        snoop_proc.lookup_or_try_init(&origin_tgid, &TRUE);
        if(lookup_tgid(tgid) == 0)
                return 0;

        info.size = *size64;
        sizes.delete(&pid_tgid);

        if (address != 0) {
                info.timestamp_ns = bpf_ktime_get_ns();
                info.stack_id = stack_traces.get_stackid(ctx, 0 | BPF_F_USER_STACK);
                allocs.update(&address, &info);
                u32 pid = pid_tgid;
                update_statistics_add(pid, info.size);
        }

        return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}
// 内存释放挂在函数
static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
        u64 addr = (u64)address;
        struct alloc_info_t *info = allocs.lookup(&addr);
        if (info == 0)
                return 0;

        allocs.delete(&addr);
        u32 pid = bpf_get_current_pid_tgid();
        update_statistics_del(pid, info->size);

        return 0;
}

// 具体的用户态内存分配相关函数的挂载函数

int malloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int malloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int free_enter(struct pt_regs *ctx, void *address) {
        return gen_free_enter(ctx, address);
}

int calloc_enter(struct pt_regs *ctx, size_t nmemb, size_t size) {
        return gen_alloc_enter(ctx, nmemb * size);
}

int calloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int realloc_enter(struct pt_regs *ctx, void *ptr, size_t size) {
        gen_free_enter(ctx, ptr);
        return gen_alloc_enter(ctx, size);
}

int realloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int posix_memalign_enter(struct pt_regs *ctx, void **memptr, size_t alignment,
                         size_t size) {
        u64 memptr64 = (u64)(size_t)memptr;
        u64 pid = bpf_get_current_pid_tgid();

        memptrs.update(&pid, &memptr64);
        return gen_alloc_enter(ctx, size);
}

int posix_memalign_exit(struct pt_regs *ctx) {
        u64 pid = bpf_get_current_pid_tgid();
        u64 *memptr64 = memptrs.lookup(&pid);
        void *addr;

        if (memptr64 == 0)
                return 0;

        memptrs.delete(&pid);

        if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
                return 0;

        u64 addr64 = (u64)(size_t)addr;
        return gen_alloc_exit2(ctx, addr64);
}

int aligned_alloc_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int aligned_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int valloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int valloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int memalign_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int memalign_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int pvalloc_enter(struct pt_regs *ctx, size_t size) {
        return gen_alloc_enter(ctx, size);
}

int pvalloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit(ctx);
}

int clear_mem(struct pt_regs *ctx)
{
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 tgid = pid_tgid >> 32, pid = pid_tgid;
        PID_FILTER
        sizes.delete(&pid_tgid);
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&pid);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        cinfo.total_size = 0 ;
        cinfo.number_of_allocs = 0;

        combined_allocs.update(&pid, &cinfo);

        snoop_proc.delete(&tgid);

    return 0;
}
"""

class MEMSnoop():
    def __init__(self):
        self.prg = text
    
    def generate_program(self):
        """生成挂载程序，主要是修改监控进程PID
        """
        self.prg = self.prg.replace("PID_FILTER", "if(pid!=%d) return" % self.snoop_pid)
        self.prg = self.prg.replace("SNOOP_PID", str(self.snoop_pid))
        self.bpf = BPF(text=self.prg)

 
    def attatch_probe(self, obj="c"):
        """将挂载函数挂载到对应的挂载点上

        Args:
        obj (str, optional): 对应内存相关函数的二进制文件. Defaults to "c".
        """
        self.bpf = BPF(text=self.prg)

        def attach_probes(sym, fn_prefix=None, can_fail=False):
                if fn_prefix is None:
                        fn_prefix = sym

                try:
                        self.bpf.attach_uprobe(name=obj, sym=sym,
                                          fn_name=fn_prefix + "_enter")
                        self.bpf.attach_uretprobe(name=obj, sym=sym,
                                             fn_name=fn_prefix + "_exit")
                except Exception:
                        if can_fail:
                                return
                        else:
                                raise

        # 用户态下监控需要监控下面这些关于内存申请与释放的函数
        attach_probes("malloc")
        attach_probes("calloc")
        attach_probes("realloc")
        attach_probes("posix_memalign")
        attach_probes("valloc", can_fail=True) # failed on Android, is deprecated in libc.so from bionic directory
        attach_probes("memalign")
        attach_probes("pvalloc", can_fail=True) # failed on Android, is deprecated in libc.so from bionic directory
        attach_probes("aligned_alloc", can_fail=True)  # added in C11
        # 挂载free函数释放内存
        self.bpf.attach_uprobe(name=obj, sym="free", fn_name="free_enter")
        self.bpf.attach_tracepoint("syscalls:sys_enter_kill", "clear_mem")

    def record(self):
        """记录并输出数据到文件
        """
        stacks = sorted(self.bpf["combined_allocs"].items(),
                        key=lambda a: -a[1].total_size)
        cur_time = time.time()
        for key, info in sorted(self.bpf["combined_allocs"].items(), key=lambda k: k[0].value):
                # BCC使用items()获取表中内容返回的k为c_uint8对象，需要使用value获取值
                self.output_file.write("%.2f,%12d,%d,%d\n" % (cur_time, key.value, info.total_size, info.number_of_allocs))    
                # print("%.2f, %d, %d\n" % (cur_time, info.total_size, info.number_of_allocs), pid)

        self.output_file.flush()

    def main_loop(self, interval):
        """
        主循环体，持续等待eBPF虚拟机传来消息，调用
        record进行输出
        """
        self.output_file.write("%s,%s,%s,%s\n" % ("ticks", "PID", "size(B)", "times"))
        while True:
            try:
                    time.sleep(interval)
            except KeyboardInterrupt:
                    if not self.output_file.closed:
                            self.output_file.close()
                    exit()
            self.record()
        # 判断监控进程的状态，如果监控进程编程僵尸进程或进程已退出，则结束监控 
            try:
                status = self.proc.status()
            except Exception:
                self.output_file.write("END")
                self.output_file.close()
                exit()
            if status == "zombie":
                self.output_file.write("END")
                self.output_file.close()
                exit()

    def run(self, interval, output_filename, snoop_pid):
        """运行方法，对外接口
        完成挂载程序生成，挂载程序，启动主循环等功能

        Args:
            output_filename (str): 输出文件名
            snoop_pid (int): 监控进程
        """
        self.proc = psutil.Process(snoop_pid)
        self.snoop_pid = snoop_pid
        self.output_file = open(output_filename, "w")
        self.generate_program()
        self.attatch_probe()
        self.main_loop(interval)

if __name__=="__main__":
    mem_snoop = MEMSnoop()
    pid = run_command_get_pid("../test_examples/fork")
    mem_snoop.run(5, "mem_new.csv", 2574335)

