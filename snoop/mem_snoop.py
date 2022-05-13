#! /bin/python3
from bcc import BPF
from time import sleep
from datetime import datetime
import resource
import argparse
import subprocess
import os
import sys
import time

from utils import run_command_get_pid, run_command

text="""
#include <uapi/linux/ptrace.h>

struct alloc_info_t {
        u64 size;
        u64 timestamp_ns;
        int stack_id;
};

struct combined_alloc_info_t {
        u64 total_size;
        u64 number_of_allocs;
};

BPF_HASH(sizes, u64);    // sizes记录某次某个pid分配的内存大小，方便在调用返回后重新获得申请的内存大小
BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);   // 记录每次分配的信息，addr->info
BPF_HASH(memptrs, u64, u64);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_HASH(combined_allocs, u64, struct combined_alloc_info_t, 10240);

// 更新某个进程栈的空间大小
static inline void update_statistics_add(u64 stack_id, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&stack_id);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        cinfo.total_size += sz;
        cinfo.number_of_allocs += 1;

        combined_allocs.update(&stack_id, &cinfo);
}
// 减小栈大小，与上面相反
static inline void update_statistics_del(u64 stack_id, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&stack_id);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        if (sz >= cinfo.total_size)
                cinfo.total_size = 0;
        else
                cinfo.total_size -= sz;

        if (cinfo.number_of_allocs > 0)
                cinfo.number_of_allocs -= 1;

        combined_allocs.update(&stack_id, &cinfo);
}

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
        SIZE_FILTER    // 大小过滤，后面用python替换成条件判断
        if (SAMPLE_EVERY_N > 1) {
                u64 ts = bpf_ktime_get_ns();
                if (ts % SAMPLE_EVERY_N != 0)
                        return 0;
        }

        u64 pid = bpf_get_current_pid_tgid();
        u64 size64 = size;
        sizes.update(&pid, &size64);

        if (SHOULD_PRINT)
                bpf_trace_printk("alloc entered, size = %u\\n", size);
        return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address) {
        u64 pid = bpf_get_current_pid_tgid();
        u64* size64 = sizes.lookup(&pid);
        struct alloc_info_t info = {0};

        if (size64 == 0)
                return 0; // missed alloc entry

        info.size = *size64;
        sizes.delete(&pid);

        if (address != 0) {
                info.timestamp_ns = bpf_ktime_get_ns();
                info.stack_id = stack_traces.get_stackid(ctx, STACK_FLAGS);
                allocs.update(&address, &info);
                update_statistics_add(info.stack_id, info.size);
        }

        if (SHOULD_PRINT) {
                bpf_trace_printk("alloc exited, size = %lu, result = %lx\\n",
                                 info.size, address);
        }
        return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
        u64 addr = (u64)address;
        struct alloc_info_t *info = allocs.lookup(&addr);
        if (info == 0)
                return 0;

        allocs.delete(&addr);
        update_statistics_del(info->stack_id, info->size);

        if (SHOULD_PRINT) {
                bpf_trace_printk("free entered, address = %lx, size = %lu\\n",
                                 address, info->size);
        }
        return 0;
}

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

"""

class Allocation(object):
    def __init__(self, stack, size):
        self.stack = stack
        self.count = 1
        self.size = size

    def update(self, size):
        self.count += 1
        self.size += size

class MEMSnoop():
    def __init__(self):
        self.prg = text
    
    def parse_args(self):
        parser = argparse.ArgumentParser(description="Attach to " +
                  "process and snoop its resource usage",
                  formatter_class=argparse.RawDescriptionHelpFormatter
                  )
        parser.add_argument("-p", "--pid", type=int, metavar="PID",
            help="id of the process to trace (optional)")
        parser.add_argument("-c", "--command",
            help="execute and trace the specified command")
        parser.add_argument("-i", "--interval", type=int, 
            help="The interval of snoop")
        args = parser.parse_args()
        if args.command is not None:
            print("Executing '%s' and tracing the resulting process." % args.command)
            popen = run_command(args.command)
            self.popens.append(popen)
            self.snoop_pid = popen.pid
        else:
            self.snoop_pid = args.pid
        self.interval = args.interval if args.interval is not None else 5

    def generate_program(self):
        self.prg = self.prg.replace("SHOULD_PRINT", "1")
        self.prg = self.prg.replace("SAMPLE_EVERY_N", str(1))
        self.prg = self.prg.replace("PAGE_SIZE", str(resource.getpagesize()))
        self.prg = self.prg.replace("STACK_FLAGS", "0"+"|BPF_F_USER_STACK")
        self.prg = self.prg.replace("SIZE_FILTER", "")
        with open("snoop_bpf", "w") as f:
                f.write(self.prg)

    def attatch_probe(self, obj="c"):
        self.bpf = BPF(text=self.prg)
        print("Attaching to pid %d, Ctrl+C to quit." % self.snoop_pid)

        def attach_probes(sym, fn_prefix=None, can_fail=False):
                if fn_prefix is None:
                        fn_prefix = sym

                try:
                        self.bpf.attach_uprobe(name=obj, sym=sym,
                                          fn_name=fn_prefix + "_enter",
                                          pid=self.snoop_pid)
                        self.bpf.attach_uretprobe(name=obj, sym=sym,
                                             fn_name=fn_prefix + "_exit",
                                             pid=self.snoop_pid)
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
        self.bpf.attach_uprobe(name=obj, sym="free", fn_name="free_enter",
                                  pid=self.snoop_pid)

    def print_outstanding(self, top_stacks=10):
        print("[%s] Top %d stacks with outstanding allocations:" %
              (datetime.now().strftime("%H:%M:%S"), top_stacks))
        alloc_info = {}
        allocs = self.bpf["allocs"]
        stack_traces = self.bpf["stack_traces"]
        for address, info in sorted(allocs.items(), key=lambda a: a[1].size):  # 实现按照字典中value结构体的size属性排序
                min_age_ns = 500 * 1e6
                if BPF.monotonic_time() - min_age_ns < info.timestamp_ns:
                        continue
                if info.stack_id < 0:
                        continue
                if info.stack_id in alloc_info:
                        alloc_info[info.stack_id].update(info.size)
                else:
                        stack = list(stack_traces.walk(info.stack_id))
                        combined = []
                        for addr in stack:
                                combined.append(self.bpf.sym(addr, pid,
                                        show_module=True, show_offset=True))
                        alloc_info[info.stack_id] = Allocation(combined,
                                                               info.size)
                # if args.show_allocs:
                #         print("\taddr = %x size = %s" %
                #               (address.value, info.size))
        to_show = sorted(alloc_info.values(),
                         key=lambda a: a.size)[-top_stacks:]
        for alloc in to_show:
                print("\t%d bytes in %d allocations from stack\n\t\t%s" %
                      (alloc.size, alloc.count,
                       b"\n\t\t".join(alloc.stack).decode("ascii")))

    def print_outstanding_combined(self, top_stacks=10):
        stack_traces = self.bpf["stack_traces"]
        stacks = sorted(self.bpf["combined_allocs"].items(),
                        key=lambda a: -a[1].total_size)
        cnt = 1
        entries = []
        for stack_id, info in stacks:
                try:
                        trace = []
                        for addr in stack_traces.walk(stack_id.value):
                                sym = self.bpf.sym(addr, self.snoop_pid,
                                                      show_module=True,
                                                      show_offset=True)
                                trace.append(sym)
                        print(trace)
                        trace = "\n\t\t".join(trace)
                except KeyError:
                        trace = "stack information lost"

                entry = ("\t%d bytes in %d allocations from stack\n\t\t%s" %
                         (info.total_size, info.number_of_allocs, trace))
                entries.append(entry)

                cnt += 1
                if cnt > top_stacks:
                    break

        print("[%s] Top %d stacks with outstanding allocations:" %
              (datetime.now().strftime("%H:%M:%S"), top_stacks))

        print('\n'.join(reversed(entries)))

    def record(self):
        stacks = sorted(self.bpf["combined_allocs"].items(),
                        key=lambda a: -a[1].total_size)
        cur_time = time.time()
        for stack_id, info in stacks:
                self.output_file.write("%.2f, %d, %d\n" % (cur_time, info.total_size, info.number_of_allocs))

        self.output_file.flush()

    def main_loop(self, interval):
        self.output_file.write("%s, %s, %s\n" % ("ticks", "size(B)", "times"))
        while True:
            try:
                    sleep(interval)
            except KeyboardInterrupt:
                    if not self.output_file.closed:
                            self.output_file.close()
                    exit()
            self.record()

    def run(self, interval, output_filename, pid):
        self.snoop_pid = pid
        self.output_file = open(output_filename, "w")
        self.generate_program()
        self.attatch_probe()
        self.main_loop(interval)

if __name__=="__main__":
    mem_snoop = MEMSnoop()
    pid = run_command_get_pid("../test_examples/mem")
#     pid = 574334
    mem_snoop.run(5, "mem.csv", pid)

