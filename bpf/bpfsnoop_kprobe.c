// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/* Copyright 2025 Leon Hwang */
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_map_helpers.h"

#include "bpfsnoop.h"
#include "bpfsnoop_arg_filter.h"
#include "bpfsnoop_arg_output.h"
#include "bpfsnoop_cfg.h"
#include "bpfsnoop_event.h"
#include "bpfsnoop_fn_args_output.h"
#include "bpfsnoop_lbr.h"
#include "bpfsnoop_pkt_filter.h"
#include "bpfsnoop_pkt_output.h"
#include "bpfsnoop_sess.h"
#include "bpfsnoop_stack.h"

volatile const __u32 PID = -1;
volatile const __u32 CPU_MASK = 0xFFFF;
volatile const __u64 FUNC_IP = 0;

__u32 ready SEC(".data.ready") = 0;

/* Must LE sysctl kernel.perf_event_max_stack = 127 */
#define MAX_STACK_DEPTH 127
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} bpfsnoop_stacks SEC(".maps");

// Kprobe specific session structure to save function arguments
struct bpfsnoop_kprobe_sess {
    __u64 session_id;
    __u64 args[MAX_FN_ARGS];  // Save function arguments for kretprobe
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPFSNOOP_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct bpfsnoop_kprobe_sess);
} bpfsnoop_kprobe_sessions SEC(".maps");

static __always_inline void
add_kprobe_session(__u64 fp, struct bpfsnoop_kprobe_sess *sess)
{
    (void) bpf_map_update_elem(&bpfsnoop_kprobe_sessions, &fp, sess, BPF_ANY);
}

static __always_inline struct bpfsnoop_kprobe_sess *
get_kprobe_session(__u64 fp)
{
    return (struct bpfsnoop_kprobe_sess *) bpf_map_lookup_elem(&bpfsnoop_kprobe_sessions, &fp);
}

static __always_inline void
delete_kprobe_session(__u64 fp)
{
    (void) bpf_map_delete_elem(&bpfsnoop_kprobe_sessions, &fp);
}

static __always_inline bool
filter(__u64 *args, __u64 session_id)
{
    return filter_arg(args) && filter_pkt(args, session_id);
}

static __always_inline __u64
get_tracee_caller_fp(struct pt_regs *ctx)
{
    u64 fp;

    fp = PT_REGS_FP(ctx);
    return fp;
}

static __always_inline __u64
gen_session_id(__u64 fp)
{
    __u32 rnd = bpf_get_prandom_u32();

    return ((__u64) rnd) << 32 | (fp & 0xFFFFFFFF);
}

static __always_inline int
emit_bpfsnoop_event(struct pt_regs *ctx)
{
    struct bpfsnoop_kprobe_sess *kprobe_sess, kprobe_sess_init = {};
    struct bpfsnoop_lbr_data *lbr;
    __u64 fp, session_id = 0;
    __u64 args[MAX_FN_ARGS];
    bool can_output = false;
    void *buffer, *ptr;
    struct event *evt;
    size_t buffer_sz;
    __u64 retval = 0;
    __u16 event_type;
    __u32 cpu, pid;

    if (!ready)
        return BPF_OK;

    cpu = bpf_get_smp_processor_id() & CPU_MASK;
    lbr = &bpfsnoop_lbr_buff[cpu];

    can_output = !cfg->both_entry_exit || cfg->is_entry;
    if (cfg->output_lbr && can_output)
        lbr->nr_bytes = bpf_get_branch_snapshot(lbr->entries, sizeof(lbr->entries), 0);

    // Initialize args array
    for (int i = 0; i < MAX_FN_ARGS; i++) {
        args[i] = 0;
    }

    // Extract arguments from pt_regs for kprobe (entry only)
    // Note: For kretprobe in single mode, parameters are not available
    if (cfg->is_entry) {
        // Note: arguments beyond register limit will remain 0
        #if defined(bpf_target_x86)
        // x86_64: Read arguments from registers using PT_REGS_PARM macros
        if (cfg->fn_args.args_nr > 0) args[0] = PT_REGS_PARM1(ctx);
        if (cfg->fn_args.args_nr > 1) args[1] = PT_REGS_PARM2(ctx);
        if (cfg->fn_args.args_nr > 2) args[2] = PT_REGS_PARM3(ctx);
        if (cfg->fn_args.args_nr > 3) args[3] = PT_REGS_PARM4(ctx);
        if (cfg->fn_args.args_nr > 4) args[4] = PT_REGS_PARM5(ctx);
        if (cfg->fn_args.args_nr > 5) args[5] = PT_REGS_PARM6(ctx);
        #elif defined(bpf_target_arm64)
        // ARM64 has 8 register arguments (X0-X7)
        if (cfg->fn_args.args_nr > 0) args[0] = PT_REGS_PARM1(ctx);
        if (cfg->fn_args.args_nr > 1) args[1] = PT_REGS_PARM2(ctx);
        if (cfg->fn_args.args_nr > 2) args[2] = PT_REGS_PARM3(ctx);
        if (cfg->fn_args.args_nr > 3) args[3] = PT_REGS_PARM4(ctx);
        if (cfg->fn_args.args_nr > 4) args[4] = PT_REGS_PARM5(ctx);
        if (cfg->fn_args.args_nr > 5) args[5] = PT_REGS_PARM6(ctx);
        if (cfg->fn_args.args_nr > 6) args[6] = PT_REGS_PARM7(ctx);
        if (cfg->fn_args.args_nr > 7) args[7] = PT_REGS_PARM8(ctx);
        #endif
    }

    if (!cfg->is_entry && cfg->fn_args.with_retval) {
        retval = PT_REGS_RC(ctx);
    }

    pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == PID)
        return BPF_OK;
    if (cfg->pid && pid != cfg->pid)
        return BPF_OK;

    fp = get_tracee_caller_fp(ctx);
    if (cfg->both_entry_exit) {
        if (cfg->is_entry) {
            // Entry: generate session_id, filter, then save session with arguments
            session_id = gen_session_id(fp);
            if (!filter(args, session_id))
                return BPF_OK;

            kprobe_sess_init.session_id = session_id;

            // Copy arguments to session for kretprobe use
            for (int i = 0; i < MAX_FN_ARGS && i < cfg->fn_args.args_nr; i++) {
                kprobe_sess_init.args[i] = args[i];
            }

            add_kprobe_session(fp, &kprobe_sess_init);
            event_type = BPFSNOOP_EVENT_TYPE_FUNC_ENTRY;
        } else {
            // Exit: retrieve session and saved arguments
            kprobe_sess = get_kprobe_session(fp);
            if (!kprobe_sess)
                return BPF_OK;

            session_id = kprobe_sess->session_id - 1;

            // Use saved arguments from entry
            for (int i = 0; i < MAX_FN_ARGS && i < cfg->fn_args.args_nr; i++) {
                args[i] = kprobe_sess->args[i];
            }

            delete_kprobe_session(fp);
            event_type = BPFSNOOP_EVENT_TYPE_FUNC_EXIT;
        }
    } else {
        // Single mode: generate session_id and filter
        session_id = gen_session_id(fp);
        // Only filter for entry in single mode, since exit args are all 0
        if (cfg->is_entry && !filter(args, session_id))
            return BPF_OK;

        event_type = cfg->is_entry ? BPFSNOOP_EVENT_TYPE_FUNC_ENTRY
                                   : BPFSNOOP_EVENT_TYPE_FUNC_EXIT;
    }

    buffer_sz = sizeof(*evt) + cfg->fn_args.buf_size + cfg->fn_args.data_size;
    buffer_sz += cfg->output_pkt ? sizeof(struct bpfsnoop_pkt_data) : 0;

    buffer = bpf_ringbuf_reserve(&bpfsnoop_events, buffer_sz, 0);
    if (!buffer)
        return BPF_OK;

    evt = buffer;
    evt->type = event_type;
    evt->length = sizeof(*evt);
    evt->kernel_ts = (__u32) bpf_ktime_get_ns();
    evt->session_id = session_id;
    evt->func_ip = FUNC_IP;
    evt->cpu = cpu;
    evt->pid = pid;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    evt->func_stack_id = -1;
    if (cfg->output_stack && cfg->is_entry)
        evt->func_stack_id = bpf_get_stackid(ctx, &bpfsnoop_stacks, BPF_F_FAST_STACK_CMP);
    if (cfg->output_lbr && can_output)
        output_lbr_data(lbr, session_id);

    ptr = buffer + sizeof(*evt);
    output_fn_args(args, ptr, retval);
    ptr += cfg->fn_args.buf_size;
    if (cfg->output_pkt) {
        output_pkt(args, ptr);
        ptr += sizeof(struct bpfsnoop_pkt_data);
    }
    if (cfg->output_arg) {
        output_arg(args, ptr);
        ptr += cfg->fn_args.data_size;
    }

    bpf_ringbuf_submit(evt, 0);

    return BPF_OK;
}

SEC("kprobe")
int bpfsnoop_kprobe(struct pt_regs *ctx)
{
    return emit_bpfsnoop_event(ctx);
}

SEC("kretprobe")
int bpfsnoop_kretprobe(struct pt_regs *ctx)
{
    return emit_bpfsnoop_event(ctx);
}

char __license[] SEC("license") = "GPL";
