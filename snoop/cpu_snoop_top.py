import os
from utils import bfs_get_procs

def cpu_top_print_header(output_file):
    output_file.write("%s,%s,%s,%s,%s,%s\n" %("TIME", "PID", "COMM", "ON CPU(invalid)", "OFF CPU(invalid)", "CPU%"))

def cpu_top_record(output_file, cur_time, snoop_pid, show_all_threads=False):
    pid_list = bfs_get_procs(snoop_pid)
    for pid in pid_list:
        try:
            if show_all_threads == False:
                rows = [os.popen('top -b -n 1 -d 0.02 -p '+str(pid)).read().split('\n')[7]]
            else:
                rows = os.popen('top -H -b -n 1 -d 0.02 -p '+str(pid)).read().split('\n')[7:]
            for row in rows:
                if row == '':
                    # print("pass")
                    continue
                else:
                    row = row.split()
                    # print(row)
                cur_pid, utilization, comm = int(row[0]), float(row[-4]), row[-1]
                if not output_file is None:
                    output_file.write("%.2f,%12d,%20s,%d,%d,%.2f\n" % (
                                    cur_time,
                                    cur_pid, 
                                    comm,
                                    -1, 
                                    -1,
                                    utilization,
                                    )
                    )
                    output_file.flush()
                else:
                    print("%.2f,%12d,%20s,%d,%d,%.2f\n" % (
                                    cur_time,
                                    pid, 
                                    comm,
                                    -1, 
                                    -1,
                                    utilization,
                                    )
                    )
        except IndexError:
            continue
    

if __name__=="__main__":
    from utils import run_command_get_pid
    from time import sleep, time
    pid = run_command_get_pid("../../test_examples/")
    usage = None
    prev_time = time()
    while True:
        sleep(1)
        cur_time = time()
        usage = cpu_top_record(None, cur_time, pid, show_all_threads=True)
        prev_time = cur_time