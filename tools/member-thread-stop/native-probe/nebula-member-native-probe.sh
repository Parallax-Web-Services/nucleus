#!/bin/bash
# SOURCE ONLY. Review/authorization required before even inventory/build/staging.
# NO execution mode: this script never starts a fixture or either helper binary.
set -euo pipefail
umask 077
[[ $# -ge 2 && $# -le 3 && $(id -u) == 0 ]] || exit 64
mode=$1
capture=$2
[[ $capture =~ ^/root/nebula-member-native-probe-[a-f0-9]{16}$ ]] || exit 64
AF91=af91d46f361e61ee552eeda78c897e21f5c633b282cc93926c322740e83fbfc9
SUPERVISOR=55fce4531ce9e0f191c8983e41b5ac098926dbbd91a819678bc4a8c25008beb8
protected() {
 local p=$1 real owner perms
 real=$(readlink -e -- "$p")
 [[ $real == "$p" ]] || return 1
 while :; do
  owner=$(stat -c %u -- "$p")
  perms=$(stat -c %a -- "$p")
  [[ $owner == 0 && $((8#$perms & 022)) == 0 ]] || return 1
  [[ $p == / ]] && break
  p=${p%/*}
  [[ -n $p ]] || p=/
 done
}
private_dir() { protected "$1" && [[ $(stat -c %u:%g:%a -- "$1") == 0:0:700 && -d $1 ]]; }
private_source() { protected "$1" && [[ -f $1 && ! -L $1 && $(stat -c %u:%g:%a:%h -- "$1") == 0:0:600:1 ]]; }
identity() { stat -c '%d:%i:%s:%Y:%Z:%u:%g:%a:%h' -- "$1"; }
check_pin() {
 local actual
 private_source "$1"
 actual=$(sha256sum -- "$1")
 [[ ${actual%% *} == "$2" ]]
}
if [[ $mode == inventory ]]; then
 [[ $# == 2 && ! -e $capture && ! -L $capture ]]
 protected /root
 mkdir -m 700 -- "$capture"
 private_dir "$capture"
 for tool in /usr/bin/stat /usr/bin/readlink /usr/bin/sha256sum /usr/bin/timeout /usr/bin/getconf /usr/bin/uname; do
  [[ -x $tool ]]
  protected "$(readlink -e -- "$tool")"
 done
 {
  printf 'source_only_plan_requires_separate_execution_authorization=true\n'
  printf 'kernel_release='; /usr/bin/uname -r
  printf 'machine='; /usr/bin/uname -m
  printf 'libc='; /usr/bin/getconf GNU_LIBC_VERSION
  printf 'python_required=false\nnetwork_required=false\npolicy_changes=false\n'
  if [[ -r /proc/sys/kernel/yama/ptrace_scope ]]; then
   IFS= read -r yama </proc/sys/kernel/yama/ptrace_scope
   [[ $yama =~ ^[0-3]$ ]]
   printf 'yama_ptrace_scope=%s\n' "$yama"
  else printf 'yama_ptrace_scope=absent\n'; fi
  cap=unset
  while read -r key rest; do [[ $key != CapEff: ]] || cap=$rest; done </proc/self/status
  [[ $cap =~ ^[a-fA-F0-9]{8,16}$ ]]
  low=${cap: -8}
  [[ $((16#$low & (1 << 19))) != 0 ]] && printf 'cap_sys_ptrace=true\n' || printf 'cap_sys_ptrace=false\n'
  found=0
  for tool in /usr/sbin/getenforce /usr/bin/getenforce; do
   if [[ -x $tool ]]; then
    protected "$(readlink -e -- "$tool")"
    value=$(/usr/bin/timeout 2s /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$tool")
    [[ $value == Enforcing || $value == Permissive || $value == Disabled ]]
    printf 'selinux=%s\n' "$value"; found=1; break
   fi
  done
  [[ $found == 1 ]] || printf 'selinux=unavailable\n'
 } >"$capture/inventory.txt"
 chmod 600 -- "$capture/inventory.txt"
 [[ -x /usr/bin/gcc ]] || { printf 'existing_compiler_available=false\n' >>"$capture/inventory.txt"; exit 2; }
 cc=$(readlink -e -- /usr/bin/gcc)
 protected "$cc"
 [[ -f $cc ]]
 printf '%s\n' "$cc" >"$capture/compiler.path"
 identity "$cc" >"$capture/compiler.identity"
 /usr/bin/timeout 3s /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$cc" -dumpversion >"$capture/compiler.version"
 printf 'existing_compiler_available=true\n' >>"$capture/inventory.txt"
 chmod 600 -- "$capture"/compiler.*
 [[ $found == 1 ]] || exit 2
 printf '{"metadata_complete":true,"policy_relaxation":false,"runtime_performed":false}\n' >"$capture/metadata-complete.json"
 chmod 600 -- "$capture/metadata-complete.json"
 # Stop here. No compilation, trace, signal, account, configuration or install.
 exit 0
fi
[[ $mode == compile && $# == 3 ]]
source_bundle=$3
[[ $source_bundle =~ ^/root/nebula-member-native-sources-[a-f0-9]{16}$ ]]
private_dir "$capture"
private_dir "$source_bundle"
for path in "$capture/compiler.path" "$capture/compiler.identity" "$capture/compiler.version" "$capture/inventory.txt" "$capture/metadata-complete.json"; do private_source "$path"; done
[[ $(cat -- "$capture/metadata-complete.json") == '{"metadata_complete":true,"policy_relaxation":false,"runtime_performed":false}' ]]
IFS= read -r cc <"$capture/compiler.path"
[[ $cc == /usr/* && -x $cc ]]
protected "$cc"
[[ $(identity "$cc") == "$(cat -- "$capture/compiler.identity")" ]]
check_pin "$source_bundle/nebula-member-thread-stop.c" "$AF91"
check_pin "$source_bundle/nebula-member-native-ownprobe.c" "$SUPERVISOR"
build=$capture/build
[[ ! -e $build && ! -L $build ]]
mkdir -m 700 -- "$build"
mkdir -m 700 -- "$build/tmp"
# These are NEW public-source copies, never profiles/keys/vendor paths.
cp -- "$source_bundle/nebula-member-thread-stop.c" "$build/source-af91.c"
cp -- "$source_bundle/nebula-member-native-ownprobe.c" "$build/source-ownprobe.c"
chmod 600 -- "$build"/*.c
check_pin "$build/source-af91.c" "$AF91"
check_pin "$build/source-ownprobe.c" "$SUPERVISOR"
cat >"$build/headers.c" <<'HEADERS'
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
static const long required[] = {PTRACE_SEIZE,PTRACE_INTERRUPT,PTRACE_GETSIGINFO,
 PTRACE_GETEVENTMSG,PTRACE_DETACH,PTRACE_O_TRACECLONE,PTRACE_O_TRACEEXEC,
 PTRACE_O_TRACEEXIT,WNOWAIT,WEXITED,WNOHANG};
int header_check(void) { return (int)(sizeof(required)/sizeof(required[0])); }
HEADERS
chmod 600 -- "$build/headers.c"
compile() {
 local label=$1
 shift
 (
  ulimit -c 0
  ulimit -f 4096
  ulimit -v 262144
  /usr/bin/timeout --signal=TERM --kill-after=2s 30s /usr/bin/env -i \
   PATH=/usr/bin:/bin LC_ALL=C HOME="$build" TMPDIR="$build/tmp" \
   "$cc" -std=c11 -Wall -Wextra -Werror -O2 "$@"
 ) >"$build/$label.stdout" 2>"$build/$label.stderr"
 chmod 600 -- "$build/$label.stdout" "$build/$label.stderr"
}
compile headers -c "$build/headers.c" -o "$build/headers.o"
compile release "$build/source-af91.c" -o "$build/thread-stop-release"
compile fixture -DNEBULA_THREAD_STOP_FIXTURE "$build/source-af91.c" -o "$build/thread-stop-fixture"
compile supervisor -pthread "$build/source-ownprobe.c" -o "$build/thread-stop-ownprobe"
[[ $(identity "$cc") == "$(cat -- "$capture/compiler.identity")" ]]
check_pin "$build/source-af91.c" "$AF91"
check_pin "$build/source-ownprobe.c" "$SUPERVISOR"
for path in "$build/thread-stop-release" "$build/thread-stop-fixture" "$build/thread-stop-ownprobe"; do
 [[ -f $path && ! -L $path && $(stat -c %u:%g:%h -- "$path") == 0:0:1 ]]
 chmod 555 -- "$path"
done
sha256sum -- "$build"/thread-stop-* >"$build/artifacts.sha256"
chmod 600 -- "$build/artifacts.sha256"
printf '{"compile_complete":true,"release_executed":false,"fixture_executed":false,"supervisor_executed":false,"policy_changed":false}\n' >"$build/compile-only.json"
chmod 600 -- "$build/compile-only.json"
# No execution path follows. Root reviews native pins/headers/compiler/policy first.
