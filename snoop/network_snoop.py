#! /bin/python3
from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep, strftime, time
from subprocess import call
from collections import namedtuple, defaultdict
from utils import run_command_get_pid

text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct throughput_key_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};
BPF_HASH(send_bytes, struct throughput_key_t);
BPF_HASH(recv_bytes, struct throughput_key_t);


TRACEPOINT_PROBE(net, net_dev_queue)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    struct throughput_key_t throughput_key = {.pid = pid};
    bpf_get_current_comm(&throughput_key.name, sizeof(throughput_key.name));

    send_bytes.increment(throughput_key, args->len);
}

TRACEPOINT_PROBE(net, netif_receive_skb)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    struct throughput_key_t throughput_key = {.pid = pid};
    bpf_get_current_comm(&throughput_key.name, sizeof(throughput_key.name));

    recv_bytes.increment(throughput_key, args->len);
}
"""
ThroughputKey = namedtuple('Throughput', ['pid', 'name'])
def get_throughput_key(k):
    return ThroughputKey(pid=k.pid, name=k.name)

class NetworkSnoop():
    def __init__(self) -> None:
        return

    def generate_program(self):
        self.prg = text
        if self.snoop_pid is not None:
            self.prg = self.prg.replace('FILTER_PID',
                'if (pid != %s) { return 0; }' % self.snoop_pid)
        else:
            self.prg = self.prg.replace('FILTER_PID', '')
        self.prg = self.prg.replace('FILTER_FAMILY', '')
        class tmp():
            cgroupmap = None
            mntnsmap = None
        tmp_arg = tmp()
        self.prg = filter_by_containers(tmp_arg) + self.prg
    
    def attatch_probe(self):
        self.bpf = BPF(text=self.prg)
        self.recv_bytes = self.bpf['recv_bytes']
        self.send_bytes = self.bpf['send_bytes']

    def record(self):
        throughput = defaultdict(lambda: [0, 0])
        for k, v in self.recv_bytes.items():
            key = get_throughput_key(k)
            throughput[key][0] = v.value
        self.recv_bytes.clear()
        for k, v in self.send_bytes.items():
            key = get_throughput_key(k)
            throughput[key][1] = v.value
        self.send_bytes.clear()
        # output
        time_ticks = time()
        for k, (send_bytes, recv_bytes) in sorted(throughput.items(),
                                                key=lambda kv: sum(kv[1]),
                                                reverse=True):
            self.output_file.write("%.2f, %d, %.12s, %.2f, %.2f\n" % (
                time_ticks,
                k.pid,
                k.name,
                (recv_bytes / 1024), (send_bytes / 1024)))
            # print("%.2f, %d, %.12s, %.2f, %.2f\n" % (
            #     time_ticks,
            #     k.pid,
            #     k.name,
            #     (recv_bytes / 1024), (send_bytes / 1024)))

    def main_loop(self):
        self.output_file.write("%s, %s, %s, %s, %s\n" % ("TICKS",
        "PID", "COMM", "RX_KB", "TX_KB"))
        # while True:
        while True:
            try:
                sleep(self.interval)
            except KeyboardInterrupt:
                if not self.output_file.closed:
                    self.output_file.close()
                exit()
            self.record()

    def run(self, interval, output_filename='net.csv', pid=None):
        self.interval = interval
        self.snoop_pid = pid
        self.generate_program()
        self.attatch_probe()
        self.output_file = open(output_filename, "w")
        self.main_loop()

if __name__=="__main__":
    pid = run_command_get_pid("python3 udp.py")
    network_snoop = NetworkSnoop()
    network_snoop.run(5, "net.csv", pid)