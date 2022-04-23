#! /bin/python3
from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep, strftime
from subprocess import call
from collections import namedtuple, defaultdict
from utils import run_command_get_pid

text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_key_t {
    u32 pid;
    char name[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);   // key=info, value=size
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);

struct ipv6_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u32 pid;
    char name[TASK_COMM_LEN];
    u16 lport;
    u16 dport;
    u64 __pad__;
};
BPF_HASH(ipv6_send_bytes, struct ipv6_key_t);
BPF_HASH(ipv6_recv_bytes, struct ipv6_key_t);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    u16 dport = 0, family = sk->__sk_common.skc_family;

    FILTER_FAMILY
    
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_send_bytes.increment(ipv4_key, size);

    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        bpf_probe_read_kernel(&ipv6_key.saddr, sizeof(ipv6_key.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.daddr, sizeof(ipv6_key.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        ipv6_send_bytes.increment(ipv6_key, size);
    }
    // else drop

    return 0;
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
/*
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    if (container_should_be_filtered()) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero = 0;

    if (copied <= 0)
        return 0;

    FILTER_FAMILY
    
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_recv_bytes.increment(ipv4_key, copied);

    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        bpf_probe_read_kernel(&ipv6_key.saddr, sizeof(ipv6_key.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.daddr, sizeof(ipv6_key.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        ipv6_recv_bytes.increment(ipv6_key, copied);
    }
    // else drop

    return 0;
}
*/
"""

TCPSessionKey = namedtuple('TCPSession', ['pid', 'name', 'laddr', 'lport', 'daddr', 'dport']) 
def get_ipv4_session_key(k):
    return TCPSessionKey(pid=k.pid,
                        name=k.name,
                        laddr=inet_ntop(AF_INET, pack("I", k.saddr)),
                        lport=k.lport,
                        daddr=inet_ntop(AF_INET, pack("I", k.daddr)),
                        dport=k.dport)

def get_ipv6_session_key(k):
    return TCPSessionKey(pid=k.pid,
                        name=k.name,
                        laddr=inet_ntop(AF_INET6, k.saddr),
                        lport=k.lport,
                        daddr=inet_ntop(AF_INET6, k.daddr),
                        dport=k.dport)  

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

        self.ipv4_send_bytes = self.bpf["ipv4_send_bytes"]
        self.ipv4_recv_bytes = self.bpf["ipv4_recv_bytes"]
        self.ipv6_send_bytes = self.bpf["ipv6_send_bytes"]
        self.ipv6_recv_bytes = self.bpf["ipv6_recv_bytes"]

    def record(self):
        # IPv4: build dict of all seen keys
        ipv4_throughput = defaultdict(lambda: [0, 0])
        for k, v in self.ipv4_send_bytes.items():
            key = get_ipv4_session_key(k)
            ipv4_throughput[key][0] = v.value
        self.ipv4_send_bytes.clear()    # 统计完流量后就把原来记录清空

        for k, v in self.ipv4_recv_bytes.items():
            key = get_ipv4_session_key(k)
            ipv4_throughput[key][1] = v.value
        self.ipv4_recv_bytes.clear()

        # IPv6: build dict of all seen keys
        ipv6_throughput = defaultdict(lambda: [0, 0])
        for k, v in self.ipv6_send_bytes.items():
            key = get_ipv6_session_key(k)
            ipv6_throughput[key][0] = v.value
        self.ipv6_send_bytes.clear()

        for k, v in self.ipv6_recv_bytes.items():
            key = get_ipv6_session_key(k)
            ipv6_throughput[key][1] = v.value
        self.ipv6_recv_bytes.clear()
        
        # Output
        for k, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
                                                key=lambda kv: sum(kv[1]),
                                                reverse=True):
            self.output_file.write("%d, %.12s, %s, %s, %d, %d\n" % (k.pid,
                k.name,
                k.laddr + ":" + str(k.lport),
                k.daddr + ":" + str(k.dport),
                int(recv_bytes / 1024), int(send_bytes / 1024)))

        for k, (send_bytes, recv_bytes) in sorted(ipv6_throughput.items(),
                                                    key=lambda kv: sum(kv[1]),
                                                    reverse=True):
            self.output_file.write("%d, %.12s, %s, %s, %d , %d\n" % (k.pid,
                k.name,
                k.laddr + ":" + str(k.lport),
                k.daddr + ":" + str(k.dport),
                int(recv_bytes / 1024), int(send_bytes / 1024)))

        self.output_file.flush()

    def main_loop(self):
        self.output_file.write("%s, %-s, %s, %s, %s, %s\n" % ("PID", "COMM",
            "LADDR6", "RADDR6", "RX_KB", "TX_KB"))
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
    pid = run_command_get_pid("python3 tcp.py")
    network_snoop = NetworkSnoop()
    network_snoop.run(5, "net.csv", pid)