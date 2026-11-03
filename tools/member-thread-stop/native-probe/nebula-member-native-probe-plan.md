# Iota native compatibility OWN probe — SOURCE ONLY

No SSH, remote staging, host inventory, native build, fixture execution or real-engine action has occurred. Only local gcc -fsyntax-only and bash -n checks were run. This packet is prepared for Root/independent review, not operational/native-host acceptance.

## Connection gate

An authorized existing Iota transport binding is UNESTABLISHED in this packet. The exact retained cPanel receipts have no target field; the saved C1 records were not mapped to Iota by guessing an index/hostname. No key bytes were read/exported and no credential search or connection occurred. Root must separately prove the existing transport/host key/account/port privately before any SSH or staging. No address/key/binding belongs in this source payload.

## Exact scope and five cases

Use ONLY the existing host compiler, existing headers/tools and current kernel/SELinux/Yama/capabilities. Never install packages, change labels/enforcement/sysctls/capabilities or call PR_SET_PTRACER. Missing/unsupported compiler or policy metadata blocks the phase; an own sibling SEIZE refusal reports blocked_existing_policy and stops without workaround.

The C supervisor forks two kinds of fresh direct children only: a fixed inert two-thread C target (no exec/fork/native service/network), and the exact compiled af91 fixture helper. It accepts no foreign PID input. It uses synthetic profiles exclusively under new /run/nebula-member-thread-test-native-XXXXXX/thread-stop-<16hex> directories. native_load_preflight=1 is solely a fixture-format input: the fake state explicitly says native_load_performed=false, and no real identity/Load or native authority is claimed.

Five native acceptance cases, in order:

1. Probe/detach both inert threads; then target exits normally through its own Q pipe.
2. One positive own-target SIGTERM: require helper exit0, exact successful termination-requested status, sigterm_queued=true, cleanup_partial=false and single_positive_tgid_queue=true; target must die SIGTERM. A queued/partial cleanup or nonzero helper result is REFUSED, retained and never automatically retried, even if the target died.
3. Targeted own-leader SIGUSR1 during acquisition; helper refuses without TERM and the target handler is observed exactly once through full target lifetime, then Q exits normally.
4. Own-target SIGSTOP during acquisition; helper refuses without TERM, target remains group-stopped/untraced. Supervisor sends CONT ONLY to that unreaped fresh inert child, then Q exits normally.
5. Prefilled unread helper stdout: af91 watchdog must exit124 within the case budget, target becomes untraced/alive and then Q exits normally. No signal-state claim is inferred from missing helper output; this case uses probe mode, which has no queue branch.

This does not repeat all modern35 adversarial cases or claim unknown outside relationship discovery. Those remain modern source/protocol evidence only. Host-native actual signal/ptrace behavior is still untested.

## Custody, cancellation and cleanup

Before either fork the supervisor sets SIGCHLD=SIG_DFL/flags0 and remains single-threaded with no asynchronous reaper. Immediately before EACH direct fork it saves its own PID; each child first arms PR_SET_PDEATHSIG(SIGKILL) and verifies getppid() still equals that saved parent, before pipe IO, target setup or fexecve. Unsupported prctl or a parent-loss race fails that child immediately. This is child-lifetime custody only, with no ptrace policy change. Abrupt supervisor loss kills its own stopped target and helper; the 20s target alarm alone is not relied on for a group-stopped target. It retains each direct positive PID unreaped until that child's last possible cleanup signal. On upstream3.10, waitid(P_PID, ownchild, WEXITED|WNOWAIT|WNOHANG) is supported for these ordinary SIGCHLD children; NO __WALL/__WCLONE is used. Only zero/no event or the exact own child with terminal CLD_EXITED/KILLED/DUMPED is accepted. ECHILD/malformed identity refuses further numeric signaling. No pidfd assumption, process-group signal or foreign PID interface exists.

On every case failure/cancellation, finish/reap the helper/tracer FIRST. Only afterward finalize target cleanup, because a traced target's terminal state may be hidden from its real parent. Forced cleanup uses SIGKILL only on an original still-owned/unreaped child after exact start/parent-terminal checks. Terminal-only waitpid reaps once and clears ownership. Failed/partial cleanup is recorded honestly; there is no broader fallback. All created scratch, raw captures and failed outputs are retained, never recursively deleted/adopted.

Supervisor TERM/INT/HUP/ALRM handlers set a cancellation flag; its nonblocking bounded event loop reaches helper-first cleanup. Targets reset their own signal dispositions and have a20s private lifetime limit. The supervisor has90s overall cancellation and11s per-case observation budgets plus2s child cleanup polls. All pipes are nonblocking except target's intentional blocking Q read and the helper stdout writer deliberately filled for case5; the parent never waits blocking on an unconfirmed terminal child. It writes no inherited stdout/stderr: only new root-private receipts. Kernel-uninterruptible stalls cannot be given a real-time guarantee; incomplete cleanup stays refused with retained own PID records, not a success claim.

Af91 cancellation is honoured through final closure. After final acceptance is committed, a later cancel may race or arrive after the one queue. Silent/nonzero/partial outcomes require independent original exit/authority proof and NEVER authorise replay. This boundary is unchanged by the supervisor; no blanket prequeue cancellation guarantee is made.

## Prospective paths and separate review gates — NOT created remotely

Public source bundle: /root/nebula-member-native-sources-0123456789abcdef (root0700; sources/script root0600).
Metadata/build capture: /root/nebula-member-native-probe-1123456789abcdef (new root0700).
Own runtime capture: /root/nebula-member-ownprobe-2123456789abcdef (new root0700).
Scratch: only new /run/nebula-member-thread-test-native-XXXXXX roots0700.
These are prospective examples; actual fresh identities must be chosen/pinned by Root before staging. Unknown existing paths refuse; no replacement/adoption or cleanup is built in.

Phase A, separately authorised metadata only:
/bin/bash --noprofile --norc <source-bundle>/nebula-member-native-probe.sh inventory <metadata-capture>

This creates only that new private capture, reads fixed kernel/architecture/libc/own-capability/Yama/SELinux metadata and the existing canonical root-protected gcc version/identity. No logs, real engine PID/profile, CA, vendor data, app env or customer DB are read. Absent compiler/policy tools returns blocked; no installation. Root reviews the actual metadata and proves host/transport identity before compile.

Phase B, separately authorised compile only:
/bin/bash --noprofile --norc <source-bundle>/nebula-member-native-probe.sh compile <metadata-capture> <source-bundle>

The script checks exact af91/supervisor source pins, private modes and retained compiler identity, requires complete metadata, and creates only an absent build directory. Clean compiler environment, existing tools only; each compile has30s plus2s kill-after, no core dump, bounded file/address limits. It builds headers.o, thread-stop-release, thread-stop-fixture and thread-stop-ownprobe. It NEVER executes any produced binary. The release variant is compile-only and must remain unexecuted throughout the own probe. Root reviews native artifact/compiler/headers/policy receipts before any fixture run.

Phase C, only after explicit Root authorization:
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/root <capture>/build/thread-stop-ownprobe --fixtures <capture>/build <own-runtime-capture>

No script run subcommand exists. The supervisor verifies canonical private build paths and exact running supervisor inode, uses a held fixture-helper FD with fexecve and a clean environment, and writes only root600 per-case raw/result receipts plus summary.json. A policy-denied own trace, partial helper result, timeout, cleanup failure or unexpected state stops the sequence. Root independently reads/reduces the private summary before any new scope. This is not real Nucleus stop permission or a production artifact installation.

## Footprint and remaining boundaries

The packet contains only public C/shell/Markdown/manifest bytes, no binaries/credentials/profiles. Runtime uses two inert target threads plus one single-thread helper and the supervisor; no Kubernetes, VM, cPanel, unit, account, hosting or monitor changes. Typical compile/runtime disk should be small; the script's per-file limits are not an aggregate filesystem quota. All paths are confined to the newly chosen root-private build/capture and generated /run fixture directories; all evidence remains for review.

Required remaining gates: independent source review; proven private existing Iota transport; separately authorised actual metadata; review of supported compiler/header/kernel/policy; actual native build review; separately authorised own fixtures; independent result/cleanup review. A later real member lifecycle/request builder with a genuine held native identity/Load proof remains a separate UNIMPLEMENTED gate. No policy-relaxation/credential-copy workaround is included. Monitoring handoff, admission, publisher and C2 retain their existing approval hold.
