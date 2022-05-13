import subprocess
import psutil

def pid_to_comm(pid):
    """根据pid查找/proc/pid/comm获取comm

    Args:
        pid (int): PID号

    Returns:
        string: comm
    """
    try:
        comm = open("/proc/%d/comm" % pid, "r").read()
        return comm
    except IOError:
        return str(pid)

def run_command_get_output(command):
    """执行命令获取输出结果

    Args:
        command (str): 待执行命令

    Returns:
        _type_: _description_
    """
    p = subprocess.Popen(command.split(),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return iter(p.stdout.readline, b'')

def run_command_get_pid(command):
    """运行命令并获取对应的进程的pid

    Args:
        command (str): 待执行命令

    Returns:
        _type_: _description_
    """
    # p = subprocess.Popen(command.split())
    p = subprocess.Popen(command.split())
    return p.pid

def run_command(command):
    p = subprocess.Popen(command.split())
    return p