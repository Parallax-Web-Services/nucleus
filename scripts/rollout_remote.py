#!/usr/bin/env python3
"""Supervise one explicitly selected member in an EXISTING live Nucleus fabric.
Only local Python is required. Remote operations use POSIX shell/Linux tools.
SIGTERM stops and revokes this run's member. Unexpected errors preserve its keys.
"""
import argparse, datetime, fcntl, importlib.util, json, os, re, signal, subprocess, sys, time, urllib.error, urllib.parse, uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("nucleus_rollout_helpers",ROOT/"scripts/test_cross_device.py")
helpers=importlib.util.module_from_spec(spec);spec.loader.exec_module(helpers)
Error=helpers.HarnessError

# Only a canonical, account-owned HOME and owned managed parents may be used.
HOME_GUARD=r"""
managed_home() {
 action=$1
 case "$HOME" in /*) ;; *) exit 50;; esac
 [ "$HOME" != / ] && [ "$(readlink -f "$HOME")" = "$HOME" ] || exit 50
 ancestor=$HOME
 while [ "$ancestor" != / ]; do
  [ -d "$ancestor" ] && [ ! -L "$ancestor" ] || exit 50
  ancestor=$(dirname "$ancestor")
 done
 [ "$(stat -c %u "$HOME")" = "$(id -u)" ] || exit 50
 base=$HOME/.local/share/nucleus-prototype
 for parent in "$HOME/.local" "$HOME/.local/share" "$base"; do
  if [ -e "$parent" ] || [ -L "$parent" ]; then
   [ -d "$parent" ] && [ ! -L "$parent" ] || exit 50
   [ "$(readlink -f "$parent")" = "$parent" ] || exit 50
   [ "$(stat -c %u "$parent")" = "$(id -u)" ] || exit 50
  else
   [ "$action" = create ] || exit 50
   mkdir -m 700 "$parent"
  fi
 done
 if [ "$action" = create ]; then chmod 700 "$base"; fi
 [ "$(stat -c %a "$base")" = 700 ] || exit 50
}
"""

COMMON=HOME_GUARD+r"""
set -eu
umask 077
root=$1
run=$2
shift 2
case "$run" in ''|*[!a-f0-9]*) exit 40;; esac
[ "${#run}" -eq 32 ] || exit 40
case "$root" in
 /tmp/nucleus-rollout.*) prefix=/tmp/nucleus-rollout.; workspace_kind=tmp;;
 /tmp/nucleus-cross-device.*) prefix=/tmp/nucleus-cross-device.; workspace_kind=owner;;
 "$HOME"/.local/share/nucleus-prototype/node.*)
  managed_home check
  prefix=$HOME/.local/share/nucleus-prototype/node.; workspace_kind=home;;
 *) exit 40;;
esac
suffix=${root#"$prefix"}
case "$suffix" in ''|*[!a-zA-Z0-9_-]*) exit 40;; esac
[ "${#suffix}" -ge 6 ] && [ "${#suffix}" -le 32 ] || exit 40
[ -d "$root" ] && [ ! -L "$root" ] || exit 40
[ "$(readlink -f "$root")" = "$root" ] || exit 40
[ "$(stat -c %u "$root")" = "$(id -u)" ] || exit 40
[ "$(stat -c %a "$root")" = 700 ] || exit 40
case "$workspace_kind" in tmp|home)
 [ -f "$root/.rollout-id" ] && [ ! -L "$root/.rollout-id" ] || exit 40
 [ "$(cat "$root/.rollout-id")" = "$run" ] || exit 40;;
esac
"""
CHECK=r"""
set -eu
[ "$(uname -s)" = Linux ] || exit 41
printf 'architecture=%s\nhostname=%s\nhome=%s\n' "$(uname -m)" "$(hostname)" "$HOME"
for item in machine_id boot_id; do
 case "$item" in machine_id) path=/etc/machine-id;; boot_id) path=/proc/sys/kernel/random/boot_id;; esac
 [ -r "$path" ] || exit 41
 value=$(tr -d '[:space:]' < "$path")
 [ -n "$value" ] || exit 41
 digest=$(printf '%s' "$value" | sha256sum)
 printf '%s_sha256=%s\n' "$item" "${digest%% *}"
done
for tool in sh sha256sum readlink mktemp awk ps stat ss setsid nohup; do command -v "$tool" >/dev/null || exit 41; done
"""
TEMP=HOME_GUARD+r"""
set -eu
umask 077
run=$1
case "$run" in ''|*[!a-f0-9]*) exit 40;; esac
[ "${#run}" -eq 32 ] || exit 40
mode=$2
case "$mode" in
 tmp) root=$(mktemp -d /tmp/nucleus-rollout.XXXXXXXXXXXX);;
 home) managed_home create; root=$(mktemp -d "$base/node.XXXXXXXXXXXX");;
 *) exit 50;;
esac
chmod 700 "$root"
printf '%s\n' "$run" > "$root/.rollout-id"
printf '%s\n' "$root"
"""
UPLOAD=COMMON+r"""
[ ! -e "$root/nucleus" ] && [ ! -e "$root/nucleus.part" ] || exit 42
(set -C; cat > "$root/nucleus.part")
digest=$(sha256sum "$root/nucleus.part")
[ "${digest%% *}" = "$1" ] || exit 42
chmod 700 "$root/nucleus.part"
mv "$root/nucleus.part" "$root/nucleus"
"""
CLI=COMMON+r"""
exec env NUCLEUS_HOME="$root/state" "$root/nucleus" "$@"
"""
FILE=COMMON+r"""
name=$1
operation=$2
case "$name" in invite.json|request.json|grant.json|member.log|rollout-"$run"-invite.json|rollout-"$run"-request.json|rollout-"$run"-grant.json) ;; *) exit 43;; esac
path=$root/$name
case "$operation" in
 write) [ ! -e "$path" ] && [ ! -L "$path" ] || exit 43; (set -C; cat > "$path"); [ "$(stat -c %s "$path")" -le 1048576 ] || exit 43;;
 read)
 [ -f "$path" ] && [ ! -L "$path" ] || exit 43
 [ "$(stat -c %u "$path")" = "$(id -u)" ] || exit 43
 if [ "$name" = member.log ]; then tail -c 65536 "$path"; else [ "$(stat -c %s "$path")" -le 1048576 ] || exit 43; cat "$path"; fi;;
 *) exit 43;;
esac
"""
PROCESS=COMMON+r"""
pid_matches() {
 [ -f "$root/member.pid" ] && [ ! -L "$root/member.pid" ] || return 1
 read pid started extra < "$root/member.pid" || return 1
 case "$pid:$started" in *[!0-9:]*|:*) return 1;; esac
 [ -z "${extra:-}" ] && [ "$pid" -gt 1 ] || return 1
 [ -r "/proc/$pid/stat" ] || return 1
 actual=$(awk '{print $22}' "/proc/$pid/stat") || return 1
 [ "$actual" = "$started" ] || return 1
 executable=$(readlink "/proc/$pid/exe") || return 1
 [ "$executable" = "$root/nucleus" ] || return 1
}
"""
START=PROCESS+r"""
if ! pid_matches; then
 rm -f "$root/member.pid"
 nohup setsid env NUCLEUS_HOME="$root/state" "$root/nucleus" run --no-open </dev/null >>"$root/member.log" 2>&1 &
 pid=$!
 n=0
 while [ "$n" -lt 50 ]; do
  if [ -r "/proc/$pid/stat" ] && [ "$(readlink "/proc/$pid/exe" 2>/dev/null || true)" = "$root/nucleus" ]; then
   started=$(awk '{print $22}' "/proc/$pid/stat")
   printf '%s %s\n' "$pid" "$started" > "$root/member.pid"
   break
  fi
  n=$((n+1)); sleep 0.1
 done
 pid_matches || exit 44
fi
printf '%s %s\n' "$pid" "$started"
"""
STOP=PROCESS+r"""
if pid_matches; then
 kill -TERM "$pid"
 n=0
 while pid_matches && [ "$n" -lt 50 ]; do sleep 0.1; n=$((n+1)); done
 if pid_matches; then kill -KILL "$pid"; fi
fi
rm -f "$root/member.pid"
"""
REMOVE=COMMON+r"""
case "$workspace_kind" in tmp|home) ;; *) exit 45;; esac
[ ! -e "$root/member.pid" ] || exit 45
cd /
rm -rf -- "$root"
"""
OWNER_FILES=COMMON+r"""
for kind in invite request grant; do
 path=$root/rollout-$run-$kind.json
 [ ! -L "$path" ] || exit 46
 if [ -e "$path" ]; then [ -f "$path" ] || exit 46; rm -- "$path"; fi
done
"""
PORT=r"""
set -eu
port=$1
mode=$2
case "$port" in ''|*[!0-9]*) exit 47;; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || exit 47
listeners=$(ss -ltnH)
printf '%s\n' "$listeners" | awk -v p="$port" -v mode="$mode" '
 $4 ~ (":" p "$") { count++; if ($4 != "127.0.0.1:" p) unsafe=1 }
 END { if(mode=="free") exit(count!=0); else exit(count!=1 || unsafe) }'
"""
def checked_workspace(value,remote_home=None):
    if re.fullmatch(r"/tmp/nucleus-rollout\.[A-Za-z0-9_-]{6,32}",value):
        return value
    if remote_home:
        from pathlib import PurePosixPath
        home=PurePosixPath(remote_home)
        if (home.is_absolute() and str(home)==remote_home and remote_home!="/"
                and ".." not in home.parts and not any(ord(c)<32 for c in remote_home)):
            pattern=re.escape(remote_home)+r"/\.local/share/nucleus-prototype/node\.[A-Za-z0-9_-]{6,32}"
            if re.fullmatch(pattern,value):
                return value
    raise Error("unsafe remote rollout workspace")
def shell(ssh,source,*args,label,data=None,timeout=30):
    return ssh.run(["sh","-c",source,"nucleus-rollout",*map(str,args)],label=label,data=data,timeout=timeout)
def parse_device(data):
    values={}
    for line in data.decode().splitlines():
        key,sep,value=line.partition("=")
        if not sep or key in values:raise Error("invalid remote preflight output")
        values[key]=value
    if values.get("architecture") not in ("x86_64","aarch64"):raise Error("unsupported remote Linux architecture")
    for key in ("machine_id_sha256","boot_id_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}",values.get(key,"")):raise Error("remote identity unavailable")
    return values
def same_device(left,right):
    return any(left.get(key) and left.get(key)==right.get(key) for key in ("machine_id_sha256","boot_id_sha256"))
def registry_change(path,action):
    path.parent.mkdir(parents=True,exist_ok=True)
    descriptor=os.open(str(path)+".lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,"a+") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        known=json.loads(path.read_text()) if path.exists() else {}
        action(known)
        helpers.write_json(path,known)
def reserve(path,target,device,run,anchors):
    def action(known):
        for other in [*anchors,*[item for item in known.values() if item.get("status")!="stopped"]]:
            if same_device(device,other):raise Error("selected SSH target duplicates an existing device or rollout")
        known[run]=dict(device,ssh_target=target,status="reserved")
    registry_change(path,action)
def registry_update(path,run,**values):
    def action(known):
        if run in known:known[run].update(values)
    registry_change(path,action)
def override_ssh(ssh,hostname=None,hostkey_alias=None):
    for key,value in (("HostName",hostname),("HostKeyAlias",hostkey_alias)):
        if value:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,252}",value):raise Error("invalid SSH hostname/host-key alias override")
            ssh.common+=["-o",key+"="+value]
    return ssh
class Rollout:
    def __init__(self,args):
        self.args=args;self.root=args.session_dir.resolve()
        self.root.mkdir(mode=0o700,parents=False,exist_ok=False)
        self.run_id=uuid.uuid4().hex;self.remote=None;self.member_id=None;self.enrolled=False
        self.tunnel=None;self.process_info=None;self.map_url=None;self.counter=0
        self.label=args.ssh_hostname or args.ssh_target
        self.registry=args.coordinator_session.parent/"rollout-members.json"
        self.coordinator=json.loads(args.coordinator_session.read_text())
        self.owner_root=helpers.checked_remote_path(self.coordinator["remote_workspace"])
        self.owner_target=helpers.validate_target(self.coordinator["ssh_target"])
        public=json.loads((args.coordinator_session.parent/"member-state/state.json").read_text())["public"]
        self.endpoint=public["endpoint"];self.fabric_id=public["fabric_id"];self.owner_id=public["owner_id"]
        parsed=urllib.parse.urlsplit(self.endpoint)
        if parsed.scheme!="https" or parsed.hostname!="127.0.0.1" or not parsed.port or parsed.path not in ("","/"):
            raise Error("existing coordinator must have a loopback HTTPS bridge endpoint")
        self.port=parsed.port;self.binary=args.binary.resolve();self.arch,self.sha=helpers.static_elf(self.binary)
        if self.binary.stat().st_size>64<<20:raise Error("binary exceeds upload limit")
        for name in ("member-ssh","owner-ssh"):(self.root/name).mkdir(mode=0o700)
        self.ssh=override_ssh(helpers.SSH(args.ssh_target,self.root/"member-ssh"),args.ssh_hostname,args.ssh_hostkey_alias)
        self.owner=helpers.SSH(self.owner_target,self.root/"owner-ssh")
        self.report={"schema_version":1,"ssh_target":args.ssh_target,"registered_name":self.label,"status":"starting",
                     "fabric_id":self.fabric_id,"owner_node_id":self.owner_id,"binary_sha256":self.sha,
                     "transport":"mutual TLS 1.3 through reverse SSH loopback forwarding and the existing coordinator bridge",
                     "remote_python_required":False,"supervision":"external Python rollout manager"}
    def remote_cli(self,*args):
        return shell(self.ssh,CLI,self.remote,self.run_id,*args,label="remote Nucleus membership command")
    def owner_cli(self,*args):
        return shell(self.owner,CLI,self.owner_root,self.run_id,*args,label="existing owner Nucleus membership command")
    def file(self,ssh,root,name,operation,data=None):
        if data is not None and len(data)>1<<20:raise Error("pairing document exceeds size limit")
        return shell(ssh,FILE,root,self.run_id,name,operation,label="transfer private pairing document",data=data)
    def reverse_command(self):
        return self.ssh.common+["-N","-o","ExitOnForwardFailure=yes","-R",f"127.0.0.1:{self.port}:127.0.0.1:{self.port}","--",self.args.ssh_target]
    def publish(self,status,error=None):
        self.report.update(status=status,prototype_running=status=="running",member_node_id=self.member_id,
                           observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        if error:self.report["error"]=str(error)
        helpers.write_json(self.args.report,self.report)
        helpers.write_json(self.root/"session.json",{
            "schema_version":1,"status":status,"manager_pid":os.getpid(),"ssh_target":self.args.ssh_target,
            "remote_workspace":self.remote,"remote_workspace_mode":getattr(self.args,"remote_workspace","tmp"),
            "member_node_id":self.member_id,"fabric_id":self.fabric_id,
            "coordinator_session":str(self.args.coordinator_session),"remote_process":self.process_info,
            "tunnel_pid":self.tunnel.pid if self.tunnel and self.tunnel.poll() is None else None,
            "remote_loopback_map_url":self.map_url,"shared_map_url":self.coordinator.get("member_map_url"),
            "stop_command":["kill","-TERM",str(os.getpid())],"restart_tunnel_command":self.reverse_command(),
            "start_remote_command":self.ssh.command(["sh","-c",START,"nucleus-rollout",self.remote,self.run_id]) if self.remote else None,
            "stop_remote_command":self.ssh.command(["sh","-c",STOP,"nucleus-rollout",self.remote,self.run_id]) if self.remote else None,
            "recovery_note":"Unexpected failure retains keys/enrollment. Restore the coordinator bridge and use guarded commands; do not create another identity."})
    def start_tunnel(self):
        shell(self.ssh,PORT,self.port,"free",label="check remote reverse-forward port")
        self.counter+=1;path=self.root/f"reverse-{self.counter:04d}.log"
        descriptor=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(descriptor,"wb") as log:
            self.tunnel=subprocess.Popen(self.reverse_command(),stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
        try:
            time.sleep(0.6)
            if self.tunnel.poll() is not None:raise Error("reverse SSH forwarding failed")
            shell(self.ssh,PORT,self.port,"loopback",label="verify reverse forward is loopback only")
        except BaseException:helpers.stop_process(self.tunnel);raise
    def start_member(self):
        values=shell(self.ssh,START,self.remote,self.run_id,label="start or verify owned member process").decode().split()
        if len(values)!=2 or not all(value.isdigit() for value in values):raise Error("invalid guarded remote PID record")
        self.process_info={"pid":int(values[0]),"start_time":values[1]}
        output=self.file(self.ssh,self.remote,"member.log","read").decode(errors="replace")
        matches=helpers.URL_PATTERN.findall(output)
        if matches:self.map_url=matches[-1]
    def online(self):
        current=json.loads(self.args.coordinator_session.read_text())
        if current.get("ssh_target")!=self.owner_target or current.get("remote_workspace")!=self.owner_root:
            raise Error("coordinator session changed to a different installation")
        self.coordinator=current
        view=helpers.fetch_map(self.coordinator["owner_map_url"])
        if view["fabric_id"]!=self.fabric_id:raise Error("existing coordinator fabric changed")
        node=helpers.node_by_id(view,self.member_id)
        return node and node.get("status")=="online"
    def supervise_once(self):
        if self.tunnel is None or self.tunnel.poll() is not None:
            self.start_tunnel()
        if self.online():
            return "running"
        self.start_member()
        return "reconnecting"
    def execute(self):
        identity=json.loads(self.owner_cli("identity"))
        if identity["node_id"]!=self.owner_id or identity["fabric_id"]!=self.fabric_id:raise Error("coordinator session identity mismatch")
        view=helpers.fetch_map(self.coordinator["owner_map_url"])
        if view.get("fabric_id")!=self.fabric_id:raise Error("existing coordinator bridge is not serving this fabric")
        members=json.loads(self.owner_cli("members"))["members"]
        if any(member["name"]==self.label for member in members.values()):raise Error("target already belongs to fabric; recover its existing state")
        device=parse_device(shell(self.ssh,CHECK,label="read selected remote identity"))
        if device["architecture"]!=self.arch:raise Error("remote architecture does not match static binary")
        if self.args.preflight and self.args.preflight.exists():
            previous=json.loads(self.args.preflight.read_text());previous=previous.get("device",previous)
            if not same_device(previous,device):raise Error("remote identity differs from approved preflight")
        evidence=json.loads(Path(self.coordinator["report"]).read_text())
        anchors=[helpers.local_device(),evidence.get("remote_device",{}),evidence.get("local_device",{})]
        reserve(self.registry,self.label,device,self.run_id,anchors);self.report["device"]=device
        shell(self.ssh,PORT,self.port,"free",label="preflight shared endpoint port")
        self.remote=checked_workspace(
            shell(self.ssh,TEMP,self.run_id,self.args.remote_workspace,label="create private remote member workspace").decode().strip(),
            device.get("home") if self.args.remote_workspace=="home" else None)
        self.publish("starting")
        shell(self.ssh,UPLOAD,self.remote,self.run_id,self.sha,label="upload verified static binary",data=self.binary.read_bytes(),timeout=60)
        version=self.remote_cli("--version").decode().strip()
        if not version.startswith("nucleus "):raise Error("remote static binary smoke test failed")
        self.report["remote_version"]=version
        self.remote_cli("init","--name",self.label);self.member_id=json.loads(self.remote_cli("identity"))["node_id"]
        prefix=f"rollout-{self.run_id}-"
        invite=prefix+"invite.json";request=prefix+"request.json";grant=prefix+"grant.json"
        self.owner_cli("invite","--endpoint",self.endpoint,"--out",self.owner_root+"/"+invite)
        self.file(self.ssh,self.remote,"invite.json","write",self.file(self.owner,self.owner_root,invite,"read"))
        self.remote_cli("join",self.remote+"/invite.json","--out",self.remote+"/request.json")
        self.file(self.owner,self.owner_root,request,"write",self.file(self.ssh,self.remote,"request.json","read"))
        inspected=json.loads(self.owner_cli("inspect",self.owner_root+"/"+request))
        if inspected.get("node_id")!=self.member_id or inspected.get("name")!=self.label:raise Error("signed join identity does not match selected remote")
        self.owner_cli("accept",self.owner_root+"/"+request,"--out",self.owner_root+"/"+grant);self.enrolled=True
        self.file(self.ssh,self.remote,"grant.json","write",self.file(self.owner,self.owner_root,grant,"read"))
        self.remote_cli("join","--accept",self.remote+"/grant.json")
        joined=json.loads(self.remote_cli("identity"))
        if joined["node_id"]!=self.member_id or joined["fabric_id"]!=self.fabric_id or joined["owner_id"]!=self.owner_id:raise Error("remote did not join existing fabric")
        registry_update(self.registry,self.run_id,node_id=self.member_id,status="enrolled")
        self.start_tunnel();self.start_member()
        helpers.wait_for(self.online,"fresh authenticated member heartbeat",timeout=35)
        self.publish("running");print(f"RUNNING: {self.label} joined the existing fabric.",flush=True)
        previous="running"
        while True:
            try:
                status=self.supervise_once()
            except (Error,OSError,ValueError,urllib.error.URLError,subprocess.TimeoutExpired):status="reconnecting"
            self.publish(status);previous=status
            time.sleep(3)
    def close(self,explicit):
        errors=[]
        if explicit:
            try:
                if self.member_id:
                    members=json.loads(self.owner_cli("members"))["members"]
                    if self.member_id in members:self.owner_cli("revoke",self.member_id)
            except (Error,OSError,ValueError) as error:errors.append(str(error))
            if self.remote:
                try:shell(self.ssh,STOP,self.remote,self.run_id,label="stop this owned remote process")
                except (Error,OSError) as error:errors.append(str(error))
            helpers.stop_process(self.tunnel)
            if self.remote and not errors:
                try:shell(self.ssh,REMOVE,self.remote,self.run_id,label="remove this verified rollout workspace")
                except (Error,OSError) as error:errors.append(str(error))
            try:shell(self.owner,OWNER_FILES,self.owner_root,self.run_id,label="remove this rollout pairing documents")
            except (Error,OSError) as error:errors.append(str(error))
            status="recovery-required" if errors else "stopped"
        else:
            helpers.stop_process(self.tunnel);status="recovery-required"
        registry_update(self.registry,self.run_id,status=status)
        if errors:self.report["cleanup_errors"]=errors
        self.report["state_preserved_for_recovery"]=status=="recovery-required";self.publish(status)
def arguments(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-target",required=True,type=helpers.validate_target)
    parser.add_argument("--remote-workspace",choices=("tmp","home"),default="tmp",
                        help="home uses a private executable HOME namespace when /tmp is noexec")
    parser.add_argument("--ssh-hostname")
    parser.add_argument("--ssh-hostkey-alias")
    parser.add_argument("--coordinator-session",required=True,type=Path)
    parser.add_argument("--session-dir",required=True,type=Path)
    parser.add_argument("--report",required=True,type=Path)
    parser.add_argument("--binary",type=Path,default=ROOT/"bin/nucleus")
    parser.add_argument("--preflight",type=Path)
    args=parser.parse_args(argv)
    for name in ("coordinator_session","session_dir","report","binary"):setattr(args,name,getattr(args,name).resolve())
    if args.preflight is None:args.preflight=ROOT/".runtime"/(args.ssh_target.split("@")[-1].split(".")[0]+"-preflight.json")
    if len(args.ssh_hostname or args.ssh_target)>128:parser.error("registered name exceeds128bytes")
    return args
def main(argv=None):
    args=arguments(argv)
    if sys.platform!="linux":raise Error("run local supervisor inside Linux or WSL")
    if args.report.exists():raise Error("choose a fresh rollout report path")
    args.report.parent.mkdir(parents=True,exist_ok=True);old_umask=os.umask(0o077)
    rollout=None;explicit=False
    def interrupted(signum,frame):raise KeyboardInterrupt
    handlers={item:signal.signal(item,interrupted) for item in (signal.SIGTERM,signal.SIGINT)}
    try:
        rollout=Rollout(args);rollout.execute()
    except KeyboardInterrupt:explicit=True;return 0
    except (Error,OSError,ValueError,KeyError,subprocess.TimeoutExpired) as error:
        if rollout:rollout.publish("recovery-required",error)
        else:helpers.write_json(args.report,{"schema_version":1,"ssh_target":args.ssh_target,"status":"failed","error":str(error)})
        print(f"Rollout requires attention: {args.ssh_target}: {error}",file=sys.stderr,flush=True);return 1
    finally:
        if rollout:rollout.close(explicit)
        for item,handler in handlers.items():signal.signal(item,handler)
        os.umask(old_umask)
    return 0
if __name__=="__main__":raise SystemExit(main())
