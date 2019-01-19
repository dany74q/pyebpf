## PyEBPF

A bcc-based, eBPF (Extended-Berkeley-Packet-Filter) wrapper for Python.

This small library serves two main purposes:

1. It lets you attach BPF kernel probes without writing native code
2. It lets you write BPF routine callbacks in Python ([1])

You may still write, compile and use your native routines 
just as you would have with bcc's BPF library, in case you need the functionality.

[1] See 'How does this library work ?' below

#### What is eBPF

Extended-Berkeley-Packet-Filters are a superset of BPF filters (traditionally available for packet-filtering), that lets you 
write small kernel-routines, using a dedicated eBPF instruction set.

To use eBPF, one needs to compile a routine, call the bpf(2) syscall, and attach a kernel-probe.

bpf(2) will make sure to take your compiled routine, statically analyze and jit it, and 
then copy it to kernel space for later use.

You attach a probe to a kernel trace event (such as a syscall invocation),
and once your probe is attached, your eBPF routine will be invoked appropriately.

Sharing data between eBPF routines, or between an eBPF routine and user-space, is possible via eBPF maps,
which operate on top of a FD that lets one communicate between those two ends.

#### What is IOVisor / BCC

BCC (BPF Compiler Collection) is a toolkit that helps you generate and use BPF routine in a user-friendly manner.

It abstracts some eBPF features (such as BPF shared data structures) via C-Macros,
and lets you focus on your routine's logic, and gathering appropriate metrics.

Code generation is managed by LLVM, hence you need an appropriate version installed.

More about the project [here](https://github.com/iovisor/bcc).  

#### How does this library work ?

Given an event to attach a kernel-probe to, this library will (In order):

1. Try to implicitly guess any extra parameters the event passes to your routine.
This is done best-effortly, by reading the */sys/kernel/debug/tracing/events/syscalls/sys_enter_<syscall>/format* file.
This file contains a text description of the parameters the event-trace may contain.

2. It will then generate a crafted native data structure, that will be populated with relevant context, including:
    - Current time in nanosecond (via bpf_ktime_get_ns)
    - PID and TID (via bpf_get_current_pid_tgid)
    - GID and UID (via bpf_get_current_uid_gid)
    - Process name (via bpf_get_current_comm)
    - Any extra implicitly guessed event-trace parameters
    e.g. for the *bind* syscall, the data structure will additionally contain a: socket FD, socket address and address length

3. It will create an eBPF shared data-structure (using the BPF_PERF_OUTPUT macro) that will be used as the communication
gateway with user mode routine

4. A dedicated polling daemon thread will be spawned, and for each output to the shared structure above, your python
callback will be invoked, passing it a ctypes class representing the native data structure

Thus, on any event your kernel probe attaches to, an internal BPF routine will be called, and in turn
it will copy all relevant members via the constructed data structure back to user mode via the BPF structure. 
Then, an internal python thread will poll on said structure, and will call the registered python callback.   

#### Using this wrapper effectively

First, install the library via:

$> pip install pyebpf

Next, import the EBPFWrapper object, instantiate it, and attach a function to an event.

```python
# trace_fields.py bcc example, using pyebpf


b = EBPFWrapper()
print 'PID MESSAGE'

def hello(data, **kwargs):
    print '{pid} Hello, World!'.format(pid=data.process_id)

b.attach_kprobe(event=b.get_syscall_fnname('clone'), fn=hello)

while True:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print 'Bye !'
        break
        



b = EBPFWrapper()
print 'COMM PID SOCKETFD'

def on_bind(data, **kwargs):
    print '{comm} {pid} {fd}'.format(comm=data.process_name, pid=data.process_id, fd=data.fd, addr=data.umyaddr)

b.attach_kprobe(event=b.get_syscall_fnname('bind'), fn=on_bind)

# Will print 'python <pid> <fd>'
s = socket()
s.bind(('0.0.0.0', 31337))

while True:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        print 'Bye !'
        break
        
# Supplying a native route

from pyebpf.ebpf_wrapper import EBPFWrapper

prog = '''
int hello(struct pt_regs* ctx) {
    bpf_trace_printk("Hello from eBPF routine!\\n");
    return 0;
}
'''
b = EBPFWrapper(text=prog)
b.attach_kprobe(event='sys_open', fn_name='hello')

while True:
    try:
        print b.trace_fields()
    except KeyboardInterrupt:
        print 'Bye !'
        break
```

#### eBPF related resources

Here are a few eBPF-related resources that I found useful during the writing of this library:

1. http://www.brendangregg.com/ebpf.htmlv
2. https://bolinfest.github.io/opensnoop-native
3. https://github.com/iovisor/bcc