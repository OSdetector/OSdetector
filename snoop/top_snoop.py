#! /bin/python3
# import threading
import multiprocessing as mp
from time import sleep, strftime, time
import argparse

from yaml import parse

from cpu_snoop import CPUSnoop
from mem_snoop import MEMSnoop
from network_snoop import NetworkSnoop
from syscall_snoop import SyscallSnoop
from utils import run_command
import subprocess

# TODO:添加'-h'选项下的使用示例
examples=""

class TOPSnoop():
    def __init__(self) -> None:
        self.cpu_snoop = CPUSnoop()
        self.mem_snoop = MEMSnoop()
        self.network_snoop = NetworkSnoop()
        self.syscall_snoop = SyscallSnoop()
        self.popens=[]
        self.parse_args()
    
    def parse_args(self):
        parser = argparse.ArgumentParser(description="Attach to " +
                  "process and snoop its resource usage",
                  formatter_class=argparse.RawDescriptionHelpFormatter,
                  epilog=examples)
        parser.add_argument("-p", "--pid", type=int, metavar="PID",
            help="id of the process to trace (optional)")
        parser.add_argument("-c", "--command",
            help="execute and trace the specified command (optional)")
        parser.add_argument("-i", "--interval", type=int, default=15,
            help="The interval of snoop (unit:s)")
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
    
    def run(self):
        cpu_snoop_process = mp.Process(target=self.cpu_snoop.run, args=(self.interval, "cpu.csv", self.snoop_pid))
        mem_snoop_process = mp.Process(target=self.mem_snoop.run, args=(self.interval, "mem.csv", self.snoop_pid))
        net_snoop_process = mp.Process(target=self.network_snoop.run, args=(self.interval, "network.csv", self.snoop_pid))
        syscall_snoop_process = mp.Process(target=self.syscall_snoop.run, args=("syscall.csv", self.snoop_pid))
        cpu_snoop_process.start()
        mem_snoop_process.start()
        net_snoop_process.start()
        syscall_snoop_process.start()


if __name__=="__main__":
    top_snoop = TOPSnoop()
    top_snoop.run()
    



