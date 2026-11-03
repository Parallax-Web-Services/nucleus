# All-thread member stop source checkpoint

This directory retains the source-reviewed all-thread stop helper and its disposable local fixtures. It is not an installer, a production request builder, or authorization to trace or stop an existing member. The predecessor leader-only helper (`e2202b88`) is unsafe for operational use and is not included as a usable alternative.

The four C files preserve their reviewed bytes. The Python harness differs from its reviewed version only in six package-relative path bindings. `SOURCE_MANIFEST.json` records their public digests, source frames and the portability changes. No binaries, real installation plans, private captures, keys or profiles belong in this source checkpoint.

## Stop protocol

The helper requires a separately approved schema-2 request and an original process-group leader identity. It retains each enumerated same-TGID task with `PTRACE_SEIZE` and the CLONE, EXEC and EXIT options, requests interruption, and validates actual kernel stop information with `PTRACE_GETSIGINFO` and `PTRACE_GETEVENTMSG`. It does not treat a sleeping `/proc` state as a stopped task.

The production helper uses no wait, waitid or waitpid calls. On upstream Linux 3.10, consuming a signal-delivery stop can clear the pending delivery value, and waitid does not accept the `__WALL`/`__WCLONE` combination needed by the intermediate design. The retained implementation instead checks an unconsumed stop through the ptrace kernel relationship.

All captured threads must be kernel-validated stopped before a fresh exact task inventory and locked `Threads` count can establish closure. Identity, pending state, executable, private beforeimages, lock and expiry checks remain required. The final group closure is checked again after the private comparisons. A changed or lost relationship, EXEC/EXIT, unexpected delivery/group stop, foreign clone or incomplete set refuses the operation; it does not adopt a smaller set or a replacement leader.

Between final acceptance and the decision, the helper performs no wait/reap, attach, detach, LISTEN, CONT or new target adoption. Termination can queue at most one `SIGTERM` to the positive original TGID, with no process-group signal or numeric fallback. It does not claim pidfd equivalence.

### Cancellation and the commit boundary

Cancellation is checked through the final closure check. Once that check passes, the termination commit has begun; a later cancellation can race with or follow the signal queue. Cancellation, a timeout, or a missing/partial report never proves that no signal was queued and never authorizes replay. The caller must independently verify process exit, current authority and fleet health before a replacement starts.

### Outside relationships and cleanup

A CLONE event naming another TGID causes refusal before an explicit signal is sent to that target. Some outside auto-attached relationships can remain unobserved, including `CLONE_PTRACE|CLONE_UNTRACED`. The result therefore always reports `outside_relationship_inventory_exhaustive=false`; it does not claim every outside process was unchanged.

Known nonsignal relationships may receive DETACH0 only after retained identity/event checks. Unknown signal, group-stop or relationship states remain unconsumed for normal tracer exit without EXITKILL. The helper does not invent a delivery signal or issue CONT to pass a refusal.

### Budgets and result meaning

The fixed bounds are 256 retained tasks, 1,024 first event observations, a three-second acquisition window, two-second private comparison windows, one-second cleanup and eight seconds overall. A deliverable SIGALRM watchdog is installed, armed and unblocked before any attachment or refusal output. It remains armed through output and actual tracer exit. These are bounded user-space/interruptible-operation budgets, not a real-time guarantee against an indefinitely stalled kernel.

- `probe-detached` means the probe queued no termination signal and completed known cleanup.
- `termination-requested` means the one queue succeeded; it does not prove graceful process exit.
- `termination-requested-partial-cleanup` and `sigterm_queued=true` still record the queue even when the helper exits with an error.
- Silent exit 124 is incomplete watchdog/reporting evidence. In terminate mode it does not generally establish whether the queue occurred. It never authorizes an automatic retry.
- Exit 125 during production watchdog setup precedes attachment. Fixture-only gates have their own use of 125 and are absent from a production build.

The caller must independently establish original-process exit and membership/fleet health before starting any replacement.

## Request and authority boundary

The production namespace is exactly:

```text
/var/lib/parallax-nebula-member-migration/thread-stop-<16lowerhex>/stop.request
```

The operation directory must be root-owned mode 0700. The request and retained state must be root-owned mode 0600; the binary beforeimage has mode 0555. Canonical nonwritable ancestor paths, full file/FD/directory identity and content checks, the held original executable and an empty root-private state lock remain mandatory. The schema-2 fields are ordered, newline-terminated `key=value` records:

```text
schema=2
pid=<original positive TGID>
start=<original leader start ticks>
uid=0
gid=0
exe_dev=<original held executable device>
exe_ino=<original held executable inode>
exe_size=<original held executable size>
checked_at=<fresh epoch seconds>
valid_until=<checked_at plus 120 seconds>
native_load_preflight=1
state=<canonical private native-home/state.json>
```

`native_load_preflight=1` is a caller attestation, not a native-identity check performed by this helper. A future separately reviewed lifecycle caller must validate the exact historical binary's native identity/Load against the real authority and bind it to these same protected beforeimages. It must not generate a hardcoded boolean in place of that check. This package supplies no production request builder, host-native release artifact, state export, identity migration or remote operation.

## Disposable modern-host fixtures

The 35 tests accept no existing PID, host, fabric, profile or network target. They create their own inert C tasks and private `/run` directories. Helper test gates are compiled only with `NEBULA_THREAD_STOP_FIXTURE`. Forced cleanup is confined to pre-held pidfds for those owned fixture children.

Requirements are Linux x86-64 with procfs, root access permitted for these own fixtures, GCC with pthread/Linux headers, and Python with `os.pidfd_open` and `signal.pidfd_send_signal`. The fixture futex assertion uses the x86-64 syscall number. The hidden-relation fixture also requires modern pidfd and WNOWAIT support. These are requirements of the tests, not a claim that pidfds or modern wait flags are used by the production helper.

Use a fresh checkout and a new, private build directory. These commands build only the fixture programs; they do not install anything or operate on an existing member:

```sh
cd tools/member-thread-stop
mkdir -m 0700 build
gcc -std=c11 -Wall -Wextra -Werror -O2 -pthread \
  -o build/nebula-member-thread-fixture-target nebula-member-thread-fixture.c
gcc -std=c11 -Wall -Wextra -Werror -O2 \
  -o build/nebula-member-thread-fixture-launch nebula-member-thread-fixture-launch.c
gcc -std=c11 -Wall -Wextra -Werror -O2 \
  -o build/nebula-member-hidden-relation-fixture nebula-member-hidden-relation-fixture.c
python3 -B test_member_thread_stop.py
```

Run the commands as root inside the intended disposable test environment. The exclusive `mkdir` should fail rather than reuse an existing build directory. The harness builds its own test-gated helper there. Build outputs, fixture-directory references and private test captures are ignored by Git and deliberately retained for review; the harness does not recursively delete them.

Coverage includes complete multithread closure/release, one positive target TERM, pending and unexpected signals, group stops, terminal/exec races, raw untraced and pthread churn, futex and bounded vfork behavior, inherited signal disposition/masks, own seccomp denial, task limits, private state/custody/schema/expiry rejection, hidden outside relationships and blocked stdout.

## Acceptance limits and primary source basis

Source review and modern local own-fixture tests are complete. Actual Iota/Linux 3.10 headers, runtime, old glibc linking and host-native binary acceptance remain untested. Modern locally built test executables are not release artifacts for that host. Existing installed helpers, coordinator/controllers, services, membership, CA and private state remain outside this package.

The protocol was checked against these upstream Linux v3.10 sources:

- [ptrace attachment, inactivity and siginfo checks](https://raw.githubusercontent.com/torvalds/linux/v3.10/kernel/ptrace.c): `ptrace_check_attach`, `ptrace_getsiginfo`, `sys_ptrace`.
- [thread publication and clone events](https://raw.githubusercontent.com/torvalds/linux/v3.10/kernel/fork.c): `copy_process`, `do_fork`.
- [wait eligibility and stop consumption](https://raw.githubusercontent.com/torvalds/linux/v3.10/kernel/exit.c): `eligible_child`, `wait_task_stopped`, `sys_waitid`, `exit_ptrace`.
- [signal-delivery cancellation](https://raw.githubusercontent.com/torvalds/linux/v3.10/kernel/signal.c): `ptrace_signal`.
- [nonleader exec and leader replacement](https://raw.githubusercontent.com/torvalds/linux/v3.10/fs/exec.c): `de_thread`.
- [locked Threads sampling](https://raw.githubusercontent.com/torvalds/linux/v3.10/fs/proc/array.c): `task_sig`.
