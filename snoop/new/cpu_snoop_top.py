import os

def cpu_top_record(output_file, cur_time, snoop_pid):
    utilization, comm = float(os.popen('top -bi -n 2 -d 0.02 -p '+str(snoop_pid)).read().split('\n')[7].split()[-4]), os.popen('top -bi -n 2 -d 0.02 -p '+str(snoop_pid)).read().split('\n')[7].split()[-1]
    if not output_file is None:
        output_file.write("%.2f,%12d,%20s,%d,%d,%.2f\n" % (
                        cur_time,
                        snoop_pid, 
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
                        snoop_pid, 
                        comm,
                        -1, 
                        -1,
                        utilization,
                        )
        )
    

if __name__=="__main__":
    from utils import run_command_get_pid
    from time import sleep, time
    pid = run_command_get_pid("../../test_examples/cpu")
    usage = None
    prev_time = time()
    while True:
        sleep(1)
        cur_time = time()
        usage = cpu_top_record(None, cur_time, pid)
        prev_time = cur_time