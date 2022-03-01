#!/usr/bin/python
from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, ntohs, AF_INET
from struct import pack
import ctypes as ct
import time 
from time import strftime
from datetime import datetime
import os
import signal
import sys

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--csv", action="store_true",
    help="comma separated values output")
args = parser.parse_args()
debug = 0


# Path were transmit and receive data will be stored
path = "./data/"

# List of IPs which are pinged
filename = "./ip_list.txt"
filehandle = open(filename, 'r')

ip_list = []
ec2_reg = ""


current_milli_time = lambda: int(round(time.time() * 1000000))
current_time = lambda: int(round(time.time()))

# Extracting machine name and IPs
count = 0
for ip in filehandle:
    if len(ip) > 5:
        ip = ip.strip("\n")
        if count == 0:
            ec2_reg = ip
            count = 1
        else:
            ip_list.append(ip)

print("%s" % (ip_list))


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    char comm[TASK_COMM_LEN];
    int retval;
    u64 daddr;
};

struct ipv4_data_t {
    u64 pid;
    u64 saddr;
    u64 daddr;
    u64 ports;
    u8 protocol;
    u64 tstamp;
    u64 tstampk;
    u8 type;
    u16 seqno;
    u16 id;
};

struct iphdr {
    #if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
            version:4;
    #elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
            ihl:4;
    #else
    #error  "Please fix <asm/byteorder.h>"
    #endif
        __u8    tos;
        __be16  tot_len;
        __be16  id;
        __be16  frag_off;
        __u8    ttl;
        __u8    protocol;
        __sum16 check;
        __be32  saddr;
        __be32  daddr;
        /*The options start here. */
};

struct icmphdr {
  __u8      type;
  __u8      code;
  __sum16   checksum;
  union {
    struct {
        __be16  id;
        __be16  sequence;
    } echo;
    __be32  gateway;
    struct {
        __be16  __unused;
        __be16  mtu;
    } frag;
    __u8    reserved[4];
  } un;
};


BPF_PERF_OUTPUT(ipv4_icmprcv_event);
BPF_PERF_OUTPUT(ipv4_ipout_event);



//**************  RECEIVE  ******************

int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    //struct iphdr *iph =  ip_hdr(skb);

    struct iphdr *iph = (struct iphdr *)(skb->head + skb->network_header);
    struct icmphdr *icmph = (struct icmphdr *)(skb->head + skb->transport_header);
    struct ipv4_data_t data4 = {};
   
    data4.saddr = iph->saddr;
    data4.daddr = iph->daddr;
    data4.pid = pid;
    data4.protocol = iph->protocol;
    data4.tstamp = skb->tstamp;
    data4.tstampk = bpf_ktime_get_ns()/1000; 
    data4.type = icmph->type;
    data4.seqno = icmph->un.echo.sequence;
    data4.id = icmph->un.echo.id;

    data4.seqno = (data4.seqno >> 8) | (data4.seqno << 8);
    data4.id = (data4.id >> 8) | (data4.id << 8);

    if(data4.protocol == 1){
        ipv4_icmprcv_event.perf_submit(ctx, &data4, sizeof(data4));
    }    
    return 0;
}

//**************  TRANSMIT  ******************

int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb){

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    //struct iphdr *iph =  ip_hdr(skb);

    struct iphdr *iph = (struct iphdr *)(skb->head + skb->network_header);
    struct icmphdr *icmph = (struct icmphdr *)(skb->head + skb->transport_header);
    struct ipv4_data_t data4 = {};
   
    data4.saddr = iph->saddr;
    data4.daddr = iph->daddr;
    data4.pid = pid;
    data4.protocol = iph->protocol;
    data4.tstamp = skb->tstamp; 
    data4.tstampk = bpf_ktime_get_ns()/1000;
    data4.type = icmph->type;
    data4.seqno = icmph->un.echo.sequence;
    data4.id = icmph->un.echo.id;

    data4.seqno = (data4.seqno >> 8) | (data4.seqno << 8);
    data4.id = (data4.id >> 8) | (data4.id << 8);

    if(data4.protocol == 1){
        ipv4_ipout_event.perf_submit(ctx, &data4, sizeof(data4));
    } 
}

"""

if debug:
    print(bpf_text)
# event data
TASK_COMM_LEN = 16      # linux/sched.h
daemon_pid = 0
warning = 0
daddr = 0

LOGSIZE = 500000
MB = 1000000

#### MB_SIZE defines the size of TX and RX files. For example, with MB_SIZE=500, when TX file size reaches 
#### 500 MB, then that TX file will be closed and a new TX file will be opened with incremented count
#### in the file name.

MB_SIZE = 500
FILE_SIZE = MB_SIZE * MB

tx_log_size = 0
rx_log_size = 0

tx_file_size = 0
rx_file_size = 0

tx_file_counter = 1
rx_file_counter = 1

rx_list = ""
tx_list = ""

now = datetime.now()
stamp = ec2_reg+"_"+str(now.year)+"-"+str(now.month)+"-"+str(now.day)+"-"+str(now.hour)

filename = str(stamp)+"_TX_"+str(tx_file_counter)+".txt"
pathTx = path+filename

filename = str(stamp)+"_RX_"+str(rx_file_counter)+".txt"
pathRx = path+filename


fileRx = open(pathRx, "w")
fileTx = open(pathTx, "w")

class Data_ipv4(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ports", ct.c_ulonglong),
        ("protocol", ct.c_uint8),
        ("tstamp", ct.c_ulonglong),
        ("tstampk", ct.c_ulonglong),
        ("type", ct.c_uint8),
        ("seqno", ct.c_uint16),
        ("id", ct.c_uint16)
    ]

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("type", ct.c_int),
        ("retval", ct.c_int),
    ]

header_string = "%-5s %-10.10s %-15s %-5s %-15s %-5s %5s"
format_string = "%-5d %-10.10s %-15s %-5d %-15s %-5d %5d %s"
format_string_1 = "%-5d %-10.10s %-15s %-5d %-15s %-5d %5d %5d %5d %5d %s"
format_string_2 = "%ld %s %s %d %d %s"

CLOCK_MONOTONIC     = 1

class timespec(ct.Structure):
    _fields_ = [
        ('tv_sec', ct.c_long),
        ('tv_nsec', ct.c_long)
    ]

librt = ct.CDLL('librt.so.1', use_errno=True)
clock_gettime = librt.clock_gettime
clock_gettime.argtypes = [ct.c_int, ct.POINTER(timespec)]

def monotonic_time():
    t = timespec()
    if clock_gettime(CLOCK_MONOTONIC , ct.pointer(t)) != 0:
        errno_ = ct.get_errno()
        raise OSError(errno_, os.strerror(errno_))
    return t.tv_sec*1000000 + t.tv_nsec/1000


if args.csv:
    header_string = "%s,%s,%s,%s,%s,%s,%s,%s"
    format_string = "%d,%s,%s,%s,%s,%s,%d,%d"

def signal_handler(sig, frame):
    global fileRx
    global fileTx
    
    fileRx.write(rx_list)
    fileTx.write(tx_list)

    fileRx.close()
    fileTx.close()
    
    print('You pressed Ctrl+C! Files closed.')
    sys.exit(0)

def get_ppid(pid):
    try:
        with open("/proc/%d/status" % pid) as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass
    return 0


###### Receive #######

def print_icmp_rcv_event(cpu, data, size):
    # print("TEST")
    check = 0
    global rx_file_counter
    global rx_file_size
    global fileRx
    global rx_log_size
    global path
    global rx_list
    global LOGSIZE
    global FILE_SIZE
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    if event.protocol == 1:
        daddr = inet_ntop(AF_INET, pack("I", event.daddr))
        saddr = inet_ntop(AF_INET, pack("I", event.saddr))
        for ip in ip_list:
            # print(ip + " " + saddr)
            if ip == saddr:
                check = 1
                break
        if check == 1:

            val = str(event.tstamp/1000)+" "+str(event.tstampk)+" "+inet_ntop(AF_INET, pack("I", event.saddr))+" "+inet_ntop(AF_INET, pack("I", event.daddr))+" "+str(event.id)+" "+str(event.seqno)+"\n"
            # print(val)
            rx_file_size = rx_file_size + len(val)
            rx_list = rx_list + val            
            rx_log_size += len(val)

            if rx_log_size > LOGSIZE:
                fileRx.write(rx_list)
                rx_list = ""

                rx_log_size = 0


                if rx_file_size > FILE_SIZE:
                    fileRx.close()
                    rx_file_size = 0
                    rx_file_counter += 1
                    now = datetime.now()
                    stamp = ec2_reg+"_"+str(now.year)+"-"+str(now.month)+"-"+str(now.day)+"-"+str(now.hour)
                    filename = str(stamp)+"_RX_"+str(rx_file_counter)+".txt"
                    pathRx = path+filename
                    fileRx = open(pathRx, "w")


###### TRANSMIT #######


def print_ipout_event(cpu, data, size):
    # print("TEST")
   
    check = 0
    global tx_file_counter
    global tx_file_size
    global tx_log_size
    global path
    global tx_list
    global fileTx
    global LOGSIZE
    global FILE_SIZE

    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    if event.protocol == 1:
        daddr = inet_ntop(AF_INET, pack("I", event.daddr))
        saddr = inet_ntop(AF_INET, pack("I", event.saddr))

        for ip in ip_list:

            if ip == daddr:
                check =1
                break
        temp_milli = int(round(time.time() * 1000000))
        tdiff = int(round(time.time() * 1000000)) - temp_milli
        
        if check == 1:
            val1 = str(event.tstamp/1000)+" "+str(event.tstampk)+" "+inet_ntop(AF_INET, pack("I", event.saddr))+" "+inet_ntop(AF_INET, pack("I", event.daddr))+" "+str(event.id)+" "+str(event.seqno)+"\n"

       
            tx_file_size = tx_file_size + len(val1)
            tx_list = tx_list + val1      
            tx_log_size += len(val1)

            if tx_log_size > LOGSIZE:
                fileTx.write(tx_list)
                tx_list = ""
                tx_log_size = 0

                if tx_file_size > FILE_SIZE:
                 
                    fileTx.close()
                    tx_file_size = 0
                    tx_file_counter += 1
                    now = datetime.now()
                    stamp = ec2_reg+"_"+str(now.year)+"-"+str(now.month)+"-"+str(now.day)+"-"+str(now.hour)
                    filename = str(stamp)+"_TX_"+str(tx_file_counter)+".txt"
                    pathTx = path+filename
                    fileTx = open(pathTx, "w")


b = BPF(text=bpf_text)


header_string = "%-15s %-15s %-15s %-5s %-5s %-10s"

# read events
b["ipv4_icmprcv_event"].open_perf_buffer(print_icmp_rcv_event)
b["ipv4_ipout_event"].open_perf_buffer(print_ipout_event) 

signal.signal(signal.SIGINT, signal_handler)

print('Press Ctrl+C')
while 1:
    b.kprobe_poll()
