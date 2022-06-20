#! /bin/python3
import multiprocessing as mp
from time import sleep
import argparse
from cpu_snoop import CPUSnoop
from mem_snoop import MEMSnoop
from network_snoop import NetworkSnoop
from syscall_snoop import SyscallSnoop
from utils import run_command

examples="""
EXAMPLES:
    ./top_snoop -c './snoop_program' # Run the program snoop_program and snoop its resource usage
    ./top_snoop -p 12345  # Snoop the process with pid 12345
    ./top_snoop -p 12345 -i 1  # Snoop the process with pid 12345 and output every 1 second
    """

class TOPSnoop():
    def __init__(self) -> None:
        """初始化类，并调用参数处理函数
        """
        self.cpu_snoop = CPUSnoop()
        self.mem_snoop = MEMSnoop()
        self.network_snoop = NetworkSnoop()
        self.syscall_snoop = SyscallSnoop()
        self.popens=[]
        self.parse_args()
    
    def parse_args(self):
        """处理输入参数
        """
        parser = argparse.ArgumentParser(description="Attach to " +
                  "process and snoop its resource usage",
                  formatter_class=argparse.RawDescriptionHelpFormatter,
                  epilog=examples)
        parser.add_argument("-p", "--pid", type=int, metavar="PID",
            help="id of the process to trace (optional)")
        parser.add_argument("-c", "--command",
            help="execute and trace the specified command (optional)")
        parser.add_argument("-i", "--interval", type=int, default=20,
            help="The interval of snoop (unit:s)")
        parser.add_argument("--cpu_output_file", help="Filename of the cpu snoop data (default:cpu.csv)")
        parser.add_argument("--mem_output_file", help="Filename of the mem snoop data (default:mem.csv)")
        parser.add_argument("--network_output_file", help="Filename of the network snoop data (default:network.csv)")
        parser.add_argument("--syscall_output_file", help="Filename of the syscall snoop data (default:syscall.csv)")
        args = parser.parse_args()
        if args.command is not None:
            print("Executing '%s' and snooping the resulting process." % args.command)
            popen = run_command(args.command)
            self.popens.append(popen)
            self.snoop_pid = popen.pid
        elif args.pid is not None:
            self.snoop_pid = args.pid
        else:
            print("Please specify the pid or command!")
            exit()
        self.interval = args.interval
        if self.interval < 20:
            print("Set interval smaller than 20 second may cause inaccuracy in CPU utilization")
        self.cpu_output_file = args.cpu_output_file if args.cpu_output_file is not None else "cpu.csv"
        self.mem_output_file = args.mem_output_file if args.mem_output_file is not None else "mem.csv"
        self.network_output_file = args.network_output_file if args.network_output_file is not None else "network.csv"
        self.syscall_output_file = args.syscall_output_file if args.syscall_output_file is not None else "syscall.csv"

        print("================================================================================")
        print("CPU_SNOOP_FILE:", self.cpu_output_file)
        print("MEM_SNOOP_FILE:", self.mem_output_file)
        print("NETWORK_SNOOP_FILE:", self.network_output_file)
        print("SYSCALL_SNOOP_FILE:", self.syscall_output_file)
        print("================================================================================")


    def run(self):
        """对外接口，启动监控进程
        使用子进程的方式来实现对多种数据同时进行监控
        """
        mp.set_start_method('spawn')   # 降低内存占用，减慢进程创建速度
        cpu_snoop_process = mp.Process(target=self.cpu_snoop.run, args=(self.interval, self.cpu_output_file, self.snoop_pid))
        # cpu_snoop_process = mp.Process(target=main, args=(self.interval, self.cpu_output_file, self.snoop_pid))
        mem_snoop_process = mp.Process(target=self.mem_snoop.run, args=(self.interval, self.mem_output_file, self.snoop_pid))
        net_snoop_process = mp.Process(target=self.network_snoop.run, args=(self.interval, self.network_output_file, self.snoop_pid))
        syscall_snoop_process = mp.Process(target=self.syscall_snoop.run, args=(self.syscall_output_file, self.snoop_pid))
        cpu_snoop_process.start()
        mem_snoop_process.start()
        net_snoop_process.start()
        syscall_snoop_process.start()


if __name__=="__main__":
    top_snoop = TOPSnoop()
    top_snoop.run()
    # sleep(10000)
# 
