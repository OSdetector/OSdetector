mem_prg = """
#ifndef _MEM_SNOOP
#define _MEM_SNOOP 1
#endif
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

BPF_HASH(sizes, u64);    // sizes记录某次某个pid_tgid分配的内存大小，方便在调用返回后重新获得申请的内存大小
BPF_HASH(allocs, u64, struct alloc_info_t, 1000000);   // 记录每次分配的信息，addr->info
BPF_HASH(memptrs, u64, u64);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_HASH(combined_allocs, u32, struct combined_alloc_info_t, 10240);  // tgid->combined_alloc_info_t

// 更新某个进程栈的空间大小
static inline void update_statistics_add(
        u32 tgid, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&tgid);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        cinfo.total_size += sz;
        cinfo.number_of_allocs += 1;

        combined_allocs.update(&tgid, &cinfo);
}
// 减小栈大小，与上面相反
static inline void update_statistics_del(u32 tgid, u64 sz) {
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&tgid);
        if (existing_cinfo != 0)
                cinfo = *existing_cinfo;

        if (sz >= cinfo.total_size)
                cinfo.total_size = 0;
        else
                cinfo.total_size -= sz;

        if (cinfo.number_of_allocs > 0)
                cinfo.number_of_allocs -= 1;

        combined_allocs.update(&tgid, &cinfo);
}

// 内存申请挂载函数，挂载在函数入口获得内存申请大小
static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
        u64 tgid_pid = bpf_get_current_pid_tgid();
        u32 pid = tgid_pid;
        u32 tgid = tgid_pid >> 32;
        u64 size64 = size;
        if(lookup_tgid(PID) == 0)
                return 0;
        if(size == 0)
        {
                bpf_trace_printk("Warning: Try to alloc zero size block, tgid:%d, pid:%d\\n", tgid, pid);
                struct combined_alloc_info_t cinfo = {
                        .total_size = PID,
                        .number_of_allocs = 0
                };
                u32 tgid = PID_MAX+2;
                combined_allocs.update(&tgid, &cinfo);
                return 0;
        }
        sizes.update(&tgid_pid, &size64);
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
        u32 pid = pid_tgid;
        // 检查是否为监控进程
        if(lookup_tgid(tgid) == 0)
                return 0;
        info.size = *size64;
        sizes.delete(&pid_tgid);

        if (address != 0) {
                info.timestamp_ns = bpf_ktime_get_ns();
                info.stack_id = stack_traces.get_stackid(ctx, 0 | BPF_F_USER_STACK);
                allocs.update(&address, &info);
                //u32 pid = pid_tgid;
                update_statistics_add(PID, info.size);
        }

        return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx) {
        return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}
// 内存释放挂载函数
static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
        u32 pid = bpf_get_current_pid_tgid();
        u32 tgid = bpf_get_current_pid_tgid()>>32;
        if(lookup_tgid(tgid) == 0)
                return 0;

        u64 addr = (u64)address;
        struct alloc_info_t *info = allocs.lookup(&addr);
        if (info == 0)
        {
                bpf_trace_printk("Warning: Try to free an memory block that doesn't belong to the process, tgid:%d, pid:%d, addr:%x\\n", tgid, pid, (int)address);
                struct combined_alloc_info_t cinfo = {
                        .total_size = PID,
                        .number_of_allocs = (u64)address
                };
                u32 tgid = PID_MAX+1;
                combined_allocs.update(&tgid, &cinfo);
                return 0;
        }

        allocs.delete(&addr);

        update_statistics_del(PID, info->size);

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

static inline int clear_mem(struct pt_regs *ctx)
{
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 tgid = pid_tgid >> 32, pid = pid_tgid;

        sizes.delete(&pid_tgid);
        struct combined_alloc_info_t *existing_cinfo;
        struct combined_alloc_info_t cinfo = {0};

        existing_cinfo = combined_allocs.lookup(&PID);
        if (existing_cinfo != 0)
                combined_allocs.delete(&tgid);
                //cinfo = *existing_cinfo;

        /*cinfo.total_size = 0;
        cinfo.number_of_allocs = 0;

        combined_allocs.update(&PID, &cinfo);*/


        return 0;
}
"""


def mem_print_header(output_file):
        output_file.write("%s,%s,%s\n" %("TIME", "SIZE(B)", "NUM"))

def mem_attach_probe(bpf_obj):
        obj='c'
        def attach_probes(sym, fn_prefix=None, can_fail=False):
                        if fn_prefix is None:
                                fn_prefix = sym

                        try:
                                bpf_obj.attach_uprobe(name=obj, sym=sym,
                                        fn_name=fn_prefix + "_enter")
                                bpf_obj.attach_uretprobe(name=obj, sym=sym,
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
        bpf_obj.attach_uprobe(name=obj, sym="free", fn_name="free_enter")
        # bpf_obj.attach_tracepoint("syscalls:sys_enter_kill", "clear_mem")

        # test uprobe
        # bpf_obj.attach_uprobe(name="./mem_example/main", sym_re="func3", fn_name="uprobe_output")
        # bpf_obj.attach_uretprobe(name="./mem_example/main", sym_re="func3", fn_name="uretprobe_output")

def mem_generate_prg(prg, configure):
        with open("/proc/sys/kernel/pid_max", "r") as f:
                global pid_max
                pid_max = int(f.read().strip())
        if configure["show_all_threads"] == True:
                prg += mem_prg.replace("PID_MAX", str(pid_max)).replace("PID", "pid")
        else:
                prg += mem_prg.replace("PID_MAX", str(pid_max)).replace("PID", "tgid")

        return prg

def mem_record(output_file, cur_time, bpf_obj):
        valid = 0
        for key, info in sorted(bpf_obj["combined_allocs"].items(), key=lambda k: k[0].value):
                # BCC使用items()获取表中内容返回的k为c_uint8对象，需要使用value获取值
                if key.value == pid_max+1:
                        print("[%.2f]Warning: Detect operation trying to free unknown memory, pid:%d, address:%x\n" % (cur_time, info.total_size, info.number_of_allocs))
                elif key.value == pid_max+2:
                        print("[%.2f]Warning: Detect operation trying to alloc a block with , pid:%d" % (cur_time, info.total_size))
                else:
                        output_file.write("%.2f,%12d,%d,%d\n" % (cur_time, key.value, info.total_size, info.number_of_allocs))
                        valid = 1    
            # print("%.2f, %d, %d\n" % (cur_time, info.total_size, info.number_of_allocs), pid)
        if valid == 0:
                for key, value in bpf_obj['snoop_proc'].items():
                        output_file.write("%.2f,%12d,%d,%d\n" % (cur_time, key.value, 0, 0))
        output_file.flush()
