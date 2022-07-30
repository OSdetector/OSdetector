from utils import pid_to_comm, bfs_get_procs
import os

# def cpu_stat_record(output_file, cur_time, snoop_pid, old_usage):
#     with open("/proc/"+str(snoop_pid)+"/stat", "r") as f:
#         line = f.read()
#         data = line.split(" ")
#         utime = int(data[13])
#         stime = int(data[14])
#         cutime = int(data[15])
#         cstime = int(data[16])
#         run_time = utime+stime+cutime+cstime
#     with open("/proc/stat", "r") as f:
#         line = f.readline()
#         data = line.split(' ')
#         user = int(data[2])
#         nice = int(data[3])
#         system = int(data[4])
#         idle = int(data[5])
#         iowait = int(data[6])
#         irq = int(data[7])
#         softirq = int(data[8])
#         total_time = user + system + nice + idle + iowait + irq + softirq
    
#     cpu_usage = {
#         "run_time": run_time,
#         "total_time": total_time,
#     }
#     if not old_usage is None:
#         cpu_usage["oncpu_time"] = run_time-old_usage["run_time"] 
#         cpu_usage["offcpu_time"] = (total_time - old_usage["total_time"])/cpu_count()- cpu_usage["oncpu_time"]
#         cpu_usage["utilization"] = cpu_usage["oncpu_time"] / (cpu_usage["oncpu_time"]+cpu_usage["offcpu_time"])
#         if not output_file is None:
#             output_file.write("%.2f,%12d,%20s,%.2f,%.2f,%.2f\n" % (
#                             cur_time,
#                             snoop_pid, 
#                             pid_to_comm(snoop_pid),
#                             cpu_usage["oncpu_time"]/os.sysconf(os.sysconf_names['SC_CLK_TCK']), 
#                             cpu_usage["offcpu_time"]/os.sysconf(os.sysconf_names['SC_CLK_TCK']),
#                             cpu_usage["utilization"] * 100,
#                             )
#             )
#             output_file.flush()
#         else:
#             print("%.2f\t%12d\t%20s\t%.2f\t%.2f\t%.2f\n" % (
#                             cur_time,
#                             snoop_pid, 
#                             pid_to_comm(snoop_pid),
#                             cpu_usage["oncpu_time"]/os.sysconf(os.sysconf_names['SC_CLK_TCK']), 
#                             cpu_usage["offcpu_time"]/os.sysconf(os.sysconf_names['SC_CLK_TCK']),
#                             cpu_usage["utilization"] * 100,
#                             )
#             )
    
#     return cpu_usage

def cpu_stat_print_header(output_file):
    output_file.write("%s,%s,%s,%s,%s,%s\n" %("TIME", "PID", "COMM", "ON CPU", "OFF CPU", "CPU%"))


def cpu_stat_record(output_file, cur_time, period, snoop_pid, old_usage):
    pid_list = bfs_get_procs(snoop_pid)
    proc_cpu_usages = {}
    for pid in pid_list:
        with open("/proc/"+str(pid)+"/stat", "r") as f:
            line = f.read()
            data = line.split(" ")
            utime = int(data[13])
            stime = int(data[14])
            cutime = int(data[15])
            cstime = int(data[16])
            run_time = utime+stime+cutime+cstime
        
        # with open("/proc/stat", "r") as f:
        #     line = f.readline()
        #     data = line.split(' ')
        #     user = int(data[2])
        #     nice = int(data[3])
        #     system = int(data[4])
        #     idle = int(data[5])
        #     iowait = int(data[6])
        #     irq = int(data[7])
        #     softirq = int(data[8])
        #     total_time = user + system + nice + idle + iowait + irq + softirq
        
        cpu_usage = {
            "run_time": run_time/os.sysconf(os.sysconf_names['SC_CLK_TCK']),
            "total_time": period,
        }
        if not old_usage is None and pid in old_usage:
            cpu_usage["oncpu_time"] = cpu_usage["run_time"]-old_usage[pid]["run_time"]
            cpu_usage["offcpu_time"] = period-cpu_usage["oncpu_time"]
            cpu_usage["utilization"] = cpu_usage["oncpu_time"] / (cpu_usage["oncpu_time"]+cpu_usage["offcpu_time"])
            if not output_file is None:
                output_file.write("%.2f,%12d,%20s,%.2f,%.2f,%.2f\n" % (
                                cur_time,
                                snoop_pid, 
                                pid_to_comm(snoop_pid),
                                cpu_usage["oncpu_time"], 
                                cpu_usage["offcpu_time"],
                                cpu_usage["utilization"] * 100,
                                )
                )
                output_file.flush()
            else:
                print("%.2f\t%12d\t%20s\t%.2f\t%.2f\t%.2f\n" % (
                                cur_time,
                                snoop_pid, 
                                pid_to_comm(snoop_pid),
                                cpu_usage["oncpu_time"], 
                                cpu_usage["offcpu_time"],
                                cpu_usage["utilization"] * 100,
                                )
                )
        proc_cpu_usages[pid] = cpu_usage
    
    return proc_cpu_usages

if __name__=="__main__":
    from utils import run_command_get_pid
    from time import sleep, time
    pid = run_command_get_pid("../../test_examples/cpu")
    usage = None
    prev_time = time()
    while True:
        sleep(1)
        cur_time = time()
        usage = cpu_stat_record(None, cur_time, cur_time-prev_time, pid, usage)
        prev_time = cur_time
