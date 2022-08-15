import re
from utils import get_delta

tracer_prg = """
#include <uapi/linux/ptrace.h>

struct TRACEE_NAME_enter_msg_data_t{
    u64 time;
    u32 tgid;
    ENTER_DATA_FIELD
};

struct TRACEE_NAME_return_msg_data_t{
    u64 time;
    u32 tgid;
    RETURN_DATA_FIELD
};

BPF_QUEUE(TRACEE_NAME_enter_msg_queue, struct TRACEE_NAME_enter_msg_data_t, 10240);
BPF_QUEUE(TRACEE_NAME_return_msg_queue, struct TRACEE_NAME_return_msg_data_t, 10240);

int TRACEE_NAME_enter(struct pt_regs* ctx)
{
    u32 tgid = bpf_get_current_pid_tgid()>>32;
    u32 pid = bpf_get_current_pid_tgid();
    if(lookup_tgid(tgid) == 0)
        return 0;
    SPID_FILTER
    struct TRACEE_NAME_enter_msg_data_t data;
    __builtin_memset(&data, 0, sizeof(data));
    data.tgid = tgid;
    data.time = bpf_ktime_get_ns();
    GET_ENTER_DATA;
    TRACEE_NAME_enter_msg_queue.push(&data, 0);

    return 0;
}

int TRACEE_NAME_return(struct pt_regs *ctx)
{
    u32 tgid = bpf_get_current_pid_tgid()>>32;
    u32 pid = bpf_get_current_pid_tgid();
    if(lookup_tgid(tgid) == 0)
        return 0;
    SPID_FILTER
    struct TRACEE_NAME_return_msg_data_t data;
    __builtin_memset(&data, 0, sizeof(data));
    data.tgid = tgid;
    data.time = bpf_ktime_get_ns();
    GET_RETURN_DATA;
    TRACEE_NAME_return_msg_queue.push(&data, 0);

    return 0;
}
"""
c_type = {"u": "unsigned int", "d": "int",
        "lu": "unsigned long", "ld": "long",
        "llu": "unsigned long long", "lld": "long long",
        "hu": "unsigned short", "hd": "short",
        "x": "unsigned int", "lx": "unsigned long",
        "llx": "unsigned long long",
        "c": "char", "K": "unsigned long long",
        "U": "unsigned long long"}

aliases_arg = {
        "arg1": "PT_REGS_PARM1(ctx)",
        "arg2": "PT_REGS_PARM2(ctx)",
        "arg3": "PT_REGS_PARM3(ctx)",
        "arg4": "PT_REGS_PARM4(ctx)",
        "arg5": "PT_REGS_PARM5(ctx)",
        "arg6": "PT_REGS_PARM6(ctx)",
        "retval": "PT_REGS_RC(ctx)",
}

aliases_indarg = {
    "arg1": "bpf_probe_read_user(&%s, sizeof(%s), &(PT_REGS_PARM1(ctx)))",
    "arg2": "bpf_probe_read_user(&%s, sizeof(%s), &(PT_REGS_PARM2(ctx)))",
    "arg3": "bpf_probe_read_user(&%s, sizeof(%s), &(PT_REGS_PARM3(ctx)))",
    "arg4": "bpf_probe_read_user(&%s, sizeof(%s), &(PT_REGS_PARM4(ctx)))",
    "arg5": "bpf_probe_read_user(&%s, sizeof(%s), &(PT_REGS_PARM5(ctx)))",
    "arg6": "bpf_probe_read_user(&%s, sizeof(%s), &(PT_REGS_PARM6(ctx)))",
    "retval": "bpf_probe_read_user(&%s, sizeof(%s), &(PT_REGS_RC(ctx)))"
}

def tracer_generate_prg(prg, configure):
    global delta
    delta = get_delta()
    trace_config = configure['trace']
    for tracee, enter_msg_format, return_msg_format in zip(trace_config['tracee_name'], trace_config['enter_msg_format'], trace_config['return_msg_format']):
        if not configure['trace']['spid'] is None:
            prg += tracer_prg.replace("SPID_FILTER", "if(pid!=%d) return 0;" % configure['probes']['spid'])
        else:
            prg += tracer_prg.replace("SPID_FILTER", "")
        name, sym = tracee.split(":")
        for format, type in zip((enter_msg_format, return_msg_format), ("enter", "return")):
            partion = format.split("\'")
            data_field = ""
            get_data = ""
            # 需要生成参数，根据用户输入生成ebpf部分代码
            if partion[0] == "":
                msg, param = partion[1], partion[2]
                data_type_list = []
                param_list = []
                for token in msg.split(" "):
                    if "%" in token:
                        data_type_list.append(token.split("%")[1])
                for token in re.findall(r'[(](.*?)[)]', param.split("%")[1])[0].split(","):
                    token = token.strip()
                    param_list.append(token)

                for data_type, param in zip(data_type_list, param_list):
                    if data_type == "s":
                        data_field += "char "+param+"[30];\n"
                        get_data += aliases_indarg[param]%("data."+param, "data."+param)+";\n"
                    else:
                        data_field += c_type[data_type] + " " + param +";\n"
                        get_data += "data."+param+"="+aliases_arg[param]+";\n"                

            if type == "enter":
                prg = prg.replace("ENTER_DATA_FIELD", data_field)
                prg = prg.replace("GET_ENTER_DATA", get_data)
            else:
                prg = prg.replace("RETURN_DATA_FIELD", data_field)
                prg = prg.replace("GET_RETURN_DATA", get_data)
            
            prg = prg.replace("TRACEE_NAME", sym)
    
    return prg

def trace_attach_probe(bpf_obj, configure):
    trace_config = configure["trace"]
    for tracee_name in trace_config["tracee_name"]:
        name, sym = tracee_name.split(":")
        bpf_obj.attach_uprobe(name=name, sym=sym, fn_name=sym + "_enter")
        bpf_obj.attach_uretprobe(name=name,
                                 sym=sym,
                                 fn_name=sym + "_return")

    return


def trace_record(output_file, bpf_obj, configure):
    trace_config = configure['trace']
    msg_list = []
    # 遍历所有trace点，收集各个队列的消息
    for tracee, enter_msg_format, return_msg_format in zip(trace_config['tracee_name'], trace_config['enter_msg_format'], trace_config['return_msg_format']):
        name, sym = tracee.split(":")
        while True:
            try:
                data = bpf_obj[sym+"_enter_msg_queue"].pop()
                enter_msg = eval(enter_msg_format.replace("arg", "data.arg")) if "\'" in enter_msg_format else enter_msg_format
                msg_list.append((data.time, "%.2f,%d," % (data.time*1e-9+delta, data.tgid) + enter_msg +"\n"))       
            except KeyError:
                try:
                    data = bpf_obj[sym+"_return_msg_queue"].pop()
                    return_msg = eval(return_msg_format.replace("retval", "data.retval")) if "\'" in return_msg_format else return_msg_format
                    msg_list.append((data.time, "%.2f,%d," % (data.time*1e-9+delta, data.tgid) + return_msg +"\n"))
                except KeyError:
                    break
                break
    # 对消息进行排序，确保按照时间顺序输出消息
    msg_list.sort(key=lambda k:k[0])
    for msg in msg_list:
        output_file.write(msg[1])
    output_file.flush()

def trace_print_header(output_file):
    output_file.write("%s,%s,%s\n" % ("TIME", "PID", "MSG"))
        
