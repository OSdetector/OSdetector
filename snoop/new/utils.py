import subprocess
import psutil
import queue
import time

def pid_to_comm(pid):
    """根据pid查找/proc/pid/comm获取comm

    Args:
        pid (int): PID号

    Returns:
        string: comm
    """
    try:
        comm = open("/proc/%d/comm" % pid, "r").read()
        return comm.replace("\n", "")
    except IOError:
        return str(pid)

def run_command_get_output(command):
    """执行命令获取输出结果

    Args:
        command (str): 待执行命令

    Returns:
        iteration: 命令的输出
    """
    p = subprocess.Popen(command.split(),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return iter(p.stdout.readline, b'')

def run_command_get_pid(command):
    """运行命令并获取对应的进程的pid

    Args:
        command (str): 待执行命令

    Returns:
        int: pid
    """
    # p = subprocess.Popen(command.split())
    p = subprocess.Popen(command.split())
    return p.pid

def run_command(command):
    """执行命令

    Args:
        command (str): 待执行命令

    Returns:
        subprocess: 进程
    """
    p = subprocess.Popen(command.split())
    return p

def bfs_get_procs(snoop_pid):
    """使用广度优先搜索获取snoop_pid进程下的所有子进程、孙子进程...

    Args:
        snoop_pid (int): 根节点进程pid

    Returns:
        list: 进程树下所有进程的pid
    """
    proc = psutil.Process(snoop_pid)
    proc_queue = queue.Queue()
    proc_queue.put(proc)
    pid_list = []
    while not proc_queue.empty():
        proc = proc_queue.get()
        pid_list.append(proc.pid)
        list(map(proc_queue.put, proc.children()))
    
    return pid_list

def get_delta():
    """获取unix时间与uptime的时间差
    unix_time = bpf_get_ktime_ns()*1e-9+delta

    Returns:
        _type_: _description_
    """
    with open("/proc/uptime", "r") as f:
        uptime = float(f.readline().split(" ")[0])
    delta = time.time() - uptime   # delta是uptime和unix epoch time的差值，因为ebpf虚拟机只能获取uptime所以在前端重新转换为unix epoch time
    return delta