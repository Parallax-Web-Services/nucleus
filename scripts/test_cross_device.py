#!/usr/bin/env python3
"""Opt-in cross-device acceptance via a selected, already-trusted SSH host.

All Nucleus listeners bind loopback; existing verified SSH carries private TLS.
No firewall, system service, authorized_keys, or default Nucleus state is changed.
Requires Linux/WSL, OpenSSH, Python 3 on the remote, and static Linux binaries.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
URL_PATTERN = re.compile(r"Resource map: (http://127[.]0[.]0[.]1:\d+/#token=[0-9a-f]{64})")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

class HarnessError(RuntimeError):
    pass

def validate_target(value):
    if not value or len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*", value):
        raise argparse.ArgumentTypeError("select an SSH alias or user@host; options and URLs are not accepted")
    return value

def checked_remote_path(value):
    if not re.fullmatch(r"/tmp/nucleus-cross-device\.[A-Za-z0-9_-]{6,32}", value):
        raise HarnessError("remote workspace is outside this harness's temporary-directory pattern")
    return value

def ssh_quote(value):
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise HarnessError("control character in SSH configuration")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

def static_elf(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
        raise HarnessError(f"{path.name}: a little-endian 64-bit Linux ELF binary is required")
    architecture = {62: "x86_64", 183: "aarch64"}.get(struct.unpack_from("<H", data, 18)[0])
    if not architecture:
        raise HarnessError("only Linux amd64 and arm64 binaries are supported")
    offset = struct.unpack_from("<Q", data, 32)[0]
    entry_size, count = struct.unpack_from("<HH", data, 54)
    if entry_size < 4 or count > 1024 or offset + entry_size * count > len(data):
        raise HarnessError("invalid ELF program-header table")
    for index in range(count):
        if struct.unpack_from("<I", data, offset + index * entry_size)[0] == 3:
            raise HarnessError(f"{path.name} is dynamically linked; rebuild with CGO_ENABLED=0")
    return architecture, hashlib.sha256(data).hexdigest()

def run_checked(argv, *, label, data=None, timeout=30):
    try:
        result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise HarnessError(f"{label} timed out") from error
    if result.returncode:
        # Private output can contain pairing capabilities or browser tokens.
        raise HarnessError(f"{label} failed (exit {result.returncode}); private output was not printed")
    if len(result.stdout) > 8 << 20 or len(result.stderr) > 1 << 20:
        raise HarnessError(f"{label} produced excessive output")
    return result.stdout

def private_write(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())

def write_json(path, value):
    temp = path.with_name(path.name + ".new")
    private_write(temp, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
    os.replace(temp, path)

def local_device():
    for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            raw = Path(candidate).read_bytes().strip()
        except OSError:
            continue
        if raw:
            break
    else:
        raise HarnessError("local machine ID is required for same-installation rejection")
    boot = Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()
    return {"hostname": socket.gethostname(), "architecture": os.uname().machine,
            "machine_id_sha256": hashlib.sha256(raw).hexdigest(),
            "boot_id_sha256": hashlib.sha256(boot).hexdigest()}

def wait_for(predicate, label, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, ValueError, KeyError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise HarnessError(f"timed out waiting for {label}")

REMOTE_CHECK = r"""
import hashlib,json,pathlib,platform,socket
for name in ("/etc/machine-id","/var/lib/dbus/machine-id"):
    try: raw=pathlib.Path(name).read_bytes().strip()
    except OSError: continue
    if raw: break
else: raise SystemExit("machine identity unavailable")
boot=pathlib.Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()
print(json.dumps({"hostname":socket.gethostname(),"architecture":platform.machine(),"machine_id_sha256":hashlib.sha256(raw).hexdigest(),"boot_id_sha256":hashlib.sha256(boot).hexdigest()}))
"""
REMOTE_TEMP = r"""
import os,tempfile
path=tempfile.mkdtemp(prefix="nucleus-cross-device.",dir="/tmp")
os.chmod(path,0o700)
print(path)
"""
REMOTE_COMMON = r"""
import os,pathlib,re,stat,sys
root=pathlib.Path(sys.argv[1])
if not re.fullmatch(r"/tmp/nucleus-cross-device\.[A-Za-z0-9_-]{6,32}",str(root)): raise SystemExit("unsafe workspace")
info=root.lstat()
if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: raise SystemExit("invalid workspace owner/mode")
"""
REMOTE_UPLOAD = REMOTE_COMMON + r"""
import hashlib
part=root/"nucleus.part"
data=sys.stdin.buffer.read(128*1024*1024+1)
if len(data)>128*1024*1024 or hashlib.sha256(data).hexdigest()!=sys.argv[2]: raise SystemExit("binary checksum mismatch")
fd=os.open(part,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)
with os.fdopen(fd,"wb") as output: output.write(data);output.flush();os.fsync(output.fileno())
os.replace(part,root/"nucleus")
"""
REMOTE_FILE = REMOTE_COMMON + r"""
name=sys.argv[2]
if name not in ("invite.json","request.json","grant.json","owner.log","owner.pid.json"): raise SystemExit("invalid file")
path=root/name
if sys.argv[3]=="read":
    if name=="owner.log" and not path.exists(): raise SystemExit(0)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.getuid(): raise SystemExit("invalid file")
    with path.open("rb") as source: data=source.read(1048577)
    if len(data)>1048576: raise SystemExit("file too large")
    sys.stdout.buffer.write(data)
elif sys.argv[3]=="write":
    data=sys.stdin.buffer.read(1048577)
    if len(data)>1048576: raise SystemExit("file too large")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as output: output.write(data);output.flush();os.fsync(output.fileno())
else: raise SystemExit("invalid operation")
"""
REMOTE_PORTS = r"""
import json,socket
listeners=[]
for _ in range(2):
    stream=socket.socket();stream.bind(("127.0.0.1",0));listeners.append(stream)
print(json.dumps([item.getsockname()[1] for item in listeners]))
"""
REMOTE_START = REMOTE_COMMON + r"""
import json,signal,subprocess
environment=dict(os.environ,NUCLEUS_HOME=str(root/"state"))
log=os.open(root/"owner.log",os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
process=subprocess.Popen([str(root/"nucleus"),"run","--no-open","--ui","127.0.0.1:"+sys.argv[2]],env=environment,stdout=log,stderr=log,start_new_session=True)
os.close(log)
def starttime(pid): return pathlib.Path("/proc/"+str(pid)+"/stat").read_text().rsplit(")",1)[1].split()[19]
record={"pid":process.pid,"starttime":starttime(process.pid),"executable":str((root/"nucleus").resolve())}
fd=os.open(root/"owner.pid.json",os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,"w") as output: json.dump(record,output);output.flush();os.fsync(output.fileno())
def terminate(signum,frame):
    try: process.terminate()
    except ProcessLookupError: pass
for signum in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP): signal.signal(signum,terminate)
try: code=process.wait()
finally:
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill();process.wait()
raise SystemExit(code)
"""
REMOTE_STOP = REMOTE_COMMON + r"""
import json,signal,time
record_path=root/"owner.pid.json"
if record_path.exists():
    info=record_path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.getuid(): raise SystemExit("invalid process record")
    record=json.loads(record_path.read_text());pid=record["pid"]
    if not isinstance(pid,int) or pid<2: raise SystemExit("invalid process ID")
    proc=pathlib.Path("/proc")/str(pid)
    def matches():
        try:
            return proc.stat().st_uid==os.getuid() and str((proc/"exe").resolve())==str((root/"nucleus").resolve()) and proc.joinpath("stat").read_text().rsplit(")",1)[1].split()[19]==record["starttime"]
        except (FileNotFoundError,ProcessLookupError): return False
    if matches():
        os.kill(pid,signal.SIGTERM)
        for _ in range(50):
            if not matches(): break
            time.sleep(.1)
        if matches(): os.kill(pid,signal.SIGKILL)
"""
REMOTE_REMOVE = REMOTE_COMMON + r"""
import shutil
shutil.rmtree(root)
"""


class SSH:
    def __init__(self, target, root):
        self.target = target
        output = run_checked(["ssh", "-G", "-T", "-o", "PermitLocalCommand=no",
                              "-o", "RemoteCommand=none", "--", target],
                             label="resolve selected SSH alias", timeout=15).decode()
        values = {}
        for line in output.splitlines():
            key, _, value = line.partition(" ")
            values.setdefault(key.lower(), []).append(value)
        for key in ("proxycommand", "proxyjump", "knownhostscommand"):
            if any(value not in ("", "none") for value in values.get(key, [])):
                raise HarnessError(f"{key} is unsupported by this direct-SSH harness")
        defaults = {}
        default_output = run_checked(["ssh", "-F", "/dev/null", "-G", "-T", "--", target],
                                     label="resolve default SSH algorithms", timeout=15).decode()
        for line in default_output.splitlines():
            key, _, value = line.partition(" ")
            defaults.setdefault(key.lower(), []).append(value)
        host, user, port = (values.get(key, [""])[0] for key in ("hostname", "user", "port"))
        if not host or not user or not port.isdigit():
            raise HarnessError("SSH alias did not resolve a hostname, user, and port")
        # This isolated config is used only for the selected target. Host * also
        # matches OpenSSH's hostname portion when the argument is user@host.
        lines = ["Host *", "  HostName " + ssh_quote(host),
                 "  User " + ssh_quote(user), "  Port " + port]
        for key in ("hostkeyalias", "identityagent", "identitiesonly",
                    "hostkeyalgorithms", "pubkeyacceptedalgorithms"):
            value = values.get(key, [""])[0]
            if key in ("hostkeyalgorithms", "pubkeyacceptedalgorithms") and values.get(key) == defaults.get(key):
                # Explicitly copying the default host-key algorithm list disables
                # OpenSSH's preference for an already-pinned key type.
                continue
            if value and (value != "none" or key == "identityagent"):
                lines.append("  " + key + " " + ssh_quote(value))
        for key in ("identityfile", "certificatefile"):
            for value in values.get(key, []):
                if value:
                    lines.append("  " + key + " " + ssh_quote(value))
        for key in ("userknownhostsfile", "globalknownhostsfile"):
            raw = values.get(key, [""])[0]
            if raw:
                paths = shlex.split(raw)
                if not paths:
                    raise HarnessError("invalid known-host path list")
                lines.append("  " + key + " " + " ".join(ssh_quote(value) for value in paths))
        self.config = root / "ssh_config"
        private_write(self.config, ("\n".join(lines) + "\n").encode())
        self.common = [
            "ssh", "-F", str(self.config), "-T",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no", "-o", "PermitLocalCommand=no",
            "-o", "RemoteCommand=none", "-o", "GatewayPorts=no",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2", "-o", "LogLevel=ERROR",
        ]

    def command(self, argv):
        return self.common + ["-o", "ClearAllForwardings=yes", "--",
                              self.target, "exec " + shlex.join(argv)]

    def run(self, argv, *, label, data=None, timeout=30):
        return run_checked(self.command(argv), label=label, data=data, timeout=timeout)

    def python(self, source, *args, label, data=None, timeout=30):
        return self.run(["python3", "-c", source, *map(str, args)],
                        label=label, data=data, timeout=timeout)

    def tunnel(self, mappings, log):
        argv = self.common + ["-N", "-o", "ExitOnForwardFailure=yes"]
        for local, remote in mappings:
            argv += ["-L", f"127.0.0.1:{local}:127.0.0.1:{remote}"]
        return subprocess.Popen(argv + ["--", self.target], stdin=subprocess.DEVNULL,
                                stdout=log, stderr=log, start_new_session=True)

def fetch_map(url):
    parsed = urllib.parse.urlsplit(url)
    token = urllib.parse.parse_qs(parsed.fragment).get("token", [""])[0]
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not re.fullmatch(r"[0-9a-f]{64}", token):
        raise HarnessError("unexpected private dashboard URL")
    request = urllib.request.Request(f"http://127.0.0.1:{parsed.port}/api/v1/fabric")
    request.add_header("Authorization", "Bearer " + token)
    with OPENER.open(request, timeout=5) as response:
        data = response.read((4 << 20) + 1)
    if len(data) > 4 << 20:
        raise HarnessError("fabric view exceeds limit")
    return json.loads(data)

def stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=6)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)

def node_by_id(view, node_id):
    return next((node for node in view["nodes"] if node["node_id"] == node_id), None)

def assert_both(view, owner_id, member_id, *, viewer_id):
    if view["local_node_id"] != viewer_id:
        return False
    required = [node_by_id(view, node_id) for node_id in (owner_id, member_id)]
    if any(node is None or node["status"] != "online" for node in required):
        return False
    # Membership can expand after first contact. Capacity includes every online
    # node, while the original pair remains the required connectivity baseline.
    online = [node for node in view["nodes"] if node["status"] == "online"]
    expected = sum(node["resources"]["cpu"]["logical_cores"] for node in online)
    if view["available_capacity"]["logical_cores"] != expected:
        raise HarnessError("available inventory differs from online node measurements")
    return view

class Session:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.ssh = SSH(args.ssh_target, root)
        self.remote = None
        self.owner_process = self.tunnel_process = self.member_process = None
        self.logs = []
        self.log_counter = 0
        self.member_home = root / "member-state"
        self.member_home.mkdir(mode=0o700)
        self.binary = args.binary.resolve()
        self.remote_binary = (args.remote_binary or args.binary).resolve()
        self.owner_url = self.member_url = None
        self.local_identity = local_device()
        self.remote_identity = None
        self.report = {"schema_version": 1, "status": "running",
                       "ssh_target": args.ssh_target,
                       "transport": "mutual TLS 1.3 inside verified SSH loopback forwarding",
                       "physical_hardware_verified": False, "checks": []}

    def log(self, name):
        self.log_counter += 1
        path = self.root / f"{self.log_counter:03d}-{name}"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        stream = os.fdopen(descriptor, "wb")
        self.logs.append(stream)
        return path, stream

    def release_log(self, stream):
        # Popen duplicates these descriptors into its child; the manager need not
        # retain a descriptor for every reconnect over a long-running demo.
        stream.close()
        self.logs.remove(stream)

    def remote_nucleus(self, *args, label):
        return self.ssh.run(["env", "NUCLEUS_HOME=" + self.remote + "/state",
                             self.remote + "/nucleus", *map(str, args)], label=label)

    def member(self, *args):
        result = subprocess.run([str(self.binary), *map(str, args)],
                                env=dict(os.environ, NUCLEUS_HOME=str(self.member_home)),
                                capture_output=True, timeout=15)
        if result.returncode:
            raise HarnessError(f"local membership command failed (exit {result.returncode})")
        return result.stdout

    def start_owner(self):
        _, stream = self.log(f"owner-session-{len(self.logs)}.log")
        self.owner_process = subprocess.Popen(
            self.ssh.command(["python3", "-c", REMOTE_START, self.remote, str(self.owner_ui_port)]),
            stdin=subprocess.DEVNULL, stdout=stream, stderr=stream, start_new_session=True,
        )
        self.release_log(stream)
        def ready():
            if self.owner_process.poll() is not None:
                raise HarnessError("remote owner session exited before startup")
            data = self.ssh.python(REMOTE_FILE, self.remote, "owner.log", "read",
                                   label="read private remote startup log")
            match = URL_PATTERN.search(data.decode(errors="replace"))
            return match.group(1) if match else None
        self.owner_url = wait_for(ready, "remote owner dashboard")

    def start_member(self):
        path, stream = self.log(f"member-{len(self.logs)}.log")
        self.member_process = subprocess.Popen(
            [str(self.binary), "run", "--no-open"],
            env=dict(os.environ, NUCLEUS_HOME=str(self.member_home)),
            stdin=subprocess.DEVNULL, stdout=stream, stderr=stream, start_new_session=True,
        )
        self.release_log(stream)
        def ready():
            if self.member_process.poll() is not None:
                raise HarnessError("local member exited before startup")
            match = URL_PATTERN.search(path.read_text(errors="replace"))
            return match.group(1) if match else None
        self.member_url = wait_for(ready, "local member dashboard")

    def start_tunnel(self):
        _, stream = self.log(f"ssh-tunnel-{len(self.logs)}.log")
        self.tunnel_process = self.ssh.tunnel(
            [(self.owner_port, self.owner_port), (self.owner_ui_port, self.owner_ui_port)], stream)
        self.release_log(stream)
        time.sleep(0.5)
        if self.tunnel_process.poll() is not None:
            raise HarnessError("SSH loopback forwarding failed")

    def owner_view(self):
        if self.tunnel_process.poll() is not None:
            raise HarnessError("SSH private transport exited")
        return fetch_map(self.owner_url)

    def check(self, name):
        self.report["checks"].append(name)
        print("PASS: " + name, flush=True)

    def publish_session(self, status):
        manifest = {
            "schema_version": 1, "status": status, "manager_pid": os.getpid(),
            "ssh_target": self.args.ssh_target, "remote_workspace": self.remote,
            "owner_map_url": self.owner_url, "member_map_url": self.member_url,
            "report": str(self.args.report), "stop_command": ["kill", "-TERM", str(os.getpid())],
            "restart_tunnel_command": self.ssh.common + ["-N", "-o", "ExitOnForwardFailure=yes",
                "-L", f"127.0.0.1:{self.owner_port}:127.0.0.1:{self.owner_port}",
                "-L", f"127.0.0.1:{self.owner_ui_port}:127.0.0.1:{self.owner_ui_port}",
                "--", self.args.ssh_target],
            "restart_owner_command": self.ssh.command(["python3", "-c", REMOTE_START,
                                                       self.remote, str(self.owner_ui_port)]),
            "stop_remote_owner_command": self.ssh.command(["python3", "-c", REMOTE_STOP, self.remote]),
            "restart_member_command": ["env", "NUCLEUS_HOME="+str(self.member_home),
                                       str(self.binary), "run", "--no-open"],
            "recovery_note": "State is retained after unexpected manager failure; these commands reuse the same keys. Stop existing managed processes before manual recovery.",
        }
        write_json(self.root / "session.json", manifest)


    def execute(self):
        local_arch, local_sha = static_elf(self.binary)
        remote_arch, remote_sha = static_elf(self.remote_binary)
        if local_arch != self.local_identity["architecture"]:
            raise HarnessError("local binary architecture differs from this device")
        self.remote_identity = json.loads(self.ssh.python(REMOTE_CHECK, label="read selected remote device identity"))
        if remote_arch != self.remote_identity["architecture"]:
            raise HarnessError("remote binary architecture differs from selected device")
        for key in ("machine_id_sha256", "boot_id_sha256"):
            if self.local_identity[key] == self.remote_identity[key]:
                raise HarnessError("selected target is the same OS installation/kernel; cross-device acceptance rejected")
        if self.local_identity["hostname"] == self.remote_identity["hostname"]:
            raise HarnessError("this acceptance run requires distinct device hostnames")
        self.report.update(local_device=self.local_identity, remote_device=self.remote_identity,
                           local_binary_sha256=local_sha, remote_binary_sha256=remote_sha,
                           distinct_os_installations_verified=True)
        self.remote = checked_remote_path(self.ssh.python(REMOTE_TEMP, label="create private remote workspace").decode().strip())
        self.ssh.python(REMOTE_UPLOAD, self.remote, remote_sha,
                        label="deploy checksum-verified prototype", data=self.remote_binary.read_bytes(), timeout=60)
        self.check("distinct remote OS identity and checksum-verified static deployment")
        self.member("init", "--name", self.local_identity["hostname"])
        self.remote_nucleus("init", "--name", self.remote_identity["hostname"], label="initialize temporary remote identity")
        self.owner_id = json.loads(self.remote_nucleus("identity", label="read remote node identity"))["node_id"]
        self.member_id = json.loads(self.member("identity"))["node_id"]
        if self.owner_id == self.member_id:
            raise HarnessError("node identities unexpectedly match")
        # Both signed transport endpoint and browser Host must use identical port numbers
        # at either end. Select remote ephemeral ports that are also free locally.
        for _ in range(20):
            ports = json.loads(self.ssh.python(REMOTE_PORTS, label="select remote loopback ports"))
            reservations = []
            try:
                for port in ports:
                    stream = socket.socket()
                    stream.bind(("127.0.0.1", port))
                    reservations.append(stream)
                self.owner_port, self.owner_ui_port = ports
                break
            except OSError:
                continue
            finally:
                for stream in reservations:
                    stream.close()
        else:
            raise HarnessError("could not select matching free loopback ports")
        self.start_tunnel()
        endpoint = f"https://127.0.0.1:{self.owner_port}"
        self.remote_nucleus("invite", "--endpoint", endpoint, "--out", self.remote+"/invite.json",
                            label="create explicit remote invitation")
        private_write(self.root/"invite.json", self.ssh.python(REMOTE_FILE, self.remote, "invite.json", "read",
                                                              label="transfer private invitation"))
        self.member("join", self.root/"invite.json", "--out", self.root/"request.json")
        if json.loads(self.member("identity"))["fabric_id"]:
            raise HarnessError("joining node accepted membership before approval")
        self.ssh.python(REMOTE_FILE, self.remote, "request.json", "write",
                        label="transfer signed join request", data=(self.root/"request.json").read_bytes())
        inspection = json.loads(self.remote_nucleus("inspect", self.remote+"/request.json",
                                                    label="verify joining identity on owner"))
        if inspection["node_id"] != self.member_id:
            raise HarnessError("owner inspection differs from independently known joining identity")
        self.remote_nucleus("accept", self.remote+"/request.json", "--out", self.remote+"/grant.json",
                            label="explicitly authorize selected joining node")
        private_write(self.root/"grant.json", self.ssh.python(REMOTE_FILE, self.remote, "grant.json", "read",
                                                             label="transfer signed grant"))
        self.member("join", "--accept", self.root/"grant.json")
        owner = json.loads(self.remote_nucleus("identity", label="verify shared fabric"))
        member = json.loads(self.member("identity"))
        if owner["fabric_id"] != member["fabric_id"]:
            raise HarnessError("owner and joining node do not share a fabric")
        self.report.update(fabric_id=owner["fabric_id"], owner_node_id=self.owner_id, member_node_id=self.member_id)
        self.check("bilateral enrollment, independent keys, shared fabric, signed identity inspection")
        self.start_owner()
        self.start_member()
        online = wait_for(lambda: assert_both(self.owner_view(), self.owner_id, self.member_id, viewer_id=self.owner_id),
                          "remote map with both real devices online")
        wait_for(lambda: assert_both(fetch_map(self.member_url), self.owner_id, self.member_id, viewer_id=self.member_id),
                 "local map with both real devices online")
        for node_id, host in ((self.owner_id, self.remote_identity["hostname"]),
                              (self.member_id, self.local_identity["hostname"])):
            if node_by_id(online, node_id)["resources"]["node"]["name"] != host:
                raise HarnessError("resource hostname differs from selected device identity")
        self.report["online_resources"] = [
            {"node_id": node["node_id"], "hostname": node["resources"]["node"]["name"],
             "logical_cores": node["resources"]["cpu"]["logical_cores"],
             "memory_total_bytes": node["resources"]["memory"]["total_bytes"]}
            for node in online["nodes"]
        ]
        self.check("distinct device telemetry and both authenticated map perspectives")
        stop_process(self.member_process)
        self.member_process = None
        def offline():
            view = self.owner_view()
            node = node_by_id(view, self.member_id)
            if not node or node["status"] != "offline":
                return False
            owner_node = node_by_id(view, self.owner_id)
            capacity = view["available_capacity"]
            if capacity["logical_cores"] != owner_node["resources"]["cpu"]["logical_cores"]:
                raise HarnessError("offline device still contributes CPU capacity")
            if capacity["memory_available_bytes"] != owner_node["resources"]["memory"]["available_bytes"]:
                raise HarnessError("offline device still contributes memory capacity")
            return view
        wait_for(offline, "disconnected device capacity removal", timeout=20)
        self.start_member()
        wait_for(lambda: assert_both(self.owner_view(), self.owner_id, self.member_id, viewer_id=self.owner_id),
                 "automatic member reconnect")
        if json.loads(self.member("identity"))["node_id"] != self.member_id:
            raise HarnessError("reconnecting changed node identity")
        self.check("disconnect removes capacity; reconnect restores it without rebuilding membership")
        if not self.args.keep_running:
            self.remote_nucleus("revoke", self.member_id, label="revoke only this temporary joining identity")
            def revoked():
                view = self.owner_view()
                if node_by_id(view, self.member_id) is not None:
                    return False
                owner_node = node_by_id(view, self.owner_id)
                if view["available_capacity"]["logical_cores"] != owner_node["resources"]["cpu"]["logical_cores"]:
                    raise HarnessError("revoked node still contributes capacity")
                return view
            wait_for(revoked, "revoked member capacity removal")
            def rejected():
                try:
                    fetch_map(self.member_url)
                except urllib.error.HTTPError as error:
                    return error.code == 503
                return False
            wait_for(rejected, "continuing member denied authenticated fabric access")
            if node_by_id(self.owner_view(), self.member_id) is not None:
                raise HarnessError("continuing revoked heartbeats restored authorization")
            self.check("revocation removes capacity and denies the still-running member")
        self.report.update(status="passed", verified_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                           prototype_running=bool(self.args.keep_running))
        write_json(self.args.report, self.report)
        if self.args.keep_running:
            self.publish_session("running")
            print("READY: live cross-device prototype; private URLs are in session.json", flush=True)
            self.supervise()

    def supervise(self):
        """Reconnect transport/processes using their existing membership, not new pairing."""
        previous = "running"
        while True:
            restarted = False
            try:
                if self.tunnel_process.poll() is not None:
                    self.start_tunnel()
                    restarted = True
                if self.owner_process.poll() is not None:
                    self.ssh.python(REMOTE_STOP, self.remote, label="stop this session's stale owner")
                    self.start_owner()
                    restarted = True
                if self.member_process.poll() is not None:
                    self.start_member()
                    restarted = True
                status = "running" if assert_both(self.owner_view(), self.owner_id, self.member_id,
                                                  viewer_id=self.owner_id) else "reconnecting"
            except (HarnessError, OSError, ValueError, urllib.error.URLError, subprocess.TimeoutExpired):
                status = "reconnecting"
            if status != previous or restarted:
                self.report["prototype_running"] = status == "running"
                write_json(self.args.report, self.report)
                self.publish_session(status)
                previous = status
            time.sleep(2)

    def close(self, *, preserve=False):
        errors = []
        stop_process(self.member_process)
        remote_stopped = True
        if self.remote:
            try:
                self.ssh.python(REMOTE_STOP, self.remote, label="stop only this run's verified remote process", timeout=15)
            except HarnessError:
                remote_stopped = False
                errors.append("remote process cleanup could not be confirmed")
        stop_process(self.owner_process)
        stop_process(self.tunnel_process)
        if self.remote and remote_stopped and not preserve:
            try:
                self.ssh.python(REMOTE_REMOVE, self.remote,
                                label="remove only this run's verified private workspace", timeout=15)
            except HarnessError:
                errors.append("remote workspace cleanup could not be confirmed")
        for stream in self.logs:
            stream.close()
        if self.args.keep_running and self.owner_url:
            self.publish_session("recovery-required" if preserve else "stopped")
        if errors:
            self.report["cleanup_errors"] = errors
        self.report["prototype_running"] = False
        self.report["state_preserved_for_recovery"] = preserve
        if self.args.report.parent.exists():
            write_json(self.args.report, self.report)
        return errors


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-target", required=True, type=validate_target,
                        help="explicitly authorized direct SSH alias or user@host")
    parser.add_argument("--binary", type=Path, default=ROOT/"bin/nucleus")
    parser.add_argument("--remote-binary", type=Path,
                        help="LOCAL static binary copied to the remote architecture")
    parser.add_argument("--report", type=Path, default=ROOT/".runtime/cross-device-report.json",
                        help="fresh redacted report path; no keys or browser tokens")
    parser.add_argument("--keep-running", action="store_true",
                        help="remain foreground supervising the live prototype until SIGTERM")
    parser.add_argument("--session-dir", type=Path,
                        help="new private local directory, required with --keep-running")
    args = parser.parse_args(argv)
    if args.keep_running and args.session_dir is None:
        parser.error("--keep-running requires a new --session-dir")
    args.report = args.report.resolve()
    args.binary = args.binary.resolve()
    if args.remote_binary:
        args.remote_binary = args.remote_binary.resolve()
    return args

def main(argv=None):
    args = arguments(argv)
    if sys.platform != "linux":
        raise HarnessError("run inside Linux or WSL")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    if args.report.exists():
        raise HarnessError("choose a fresh report path; existing reports are not overwritten")
    original_umask = os.umask(0o077)
    session = None
    temporary = None
    explicit_stop = False
    failed = False
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    previous = {signum: signal.signal(signum, interrupted)
                for signum in (signal.SIGTERM, signal.SIGINT)}
    try:
        if args.session_dir:
            root = args.session_dir.resolve()
            root.mkdir(mode=0o700, parents=False, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix="nucleus-cross-device-local-")
            root = Path(temporary.name)
        session = Session(args, root)
        session.execute()
        return 0
    except KeyboardInterrupt:
        explicit_stop = True
        return 0 if session and session.report.get("status") == "passed" else 130
    except (HarnessError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        failed = True
        if session:
            session.report.update(status="failed", error=str(error))
        print("Cross-device validation failed: " + str(error), file=sys.stderr)
        return 1
    finally:
        # Unexpected failures in a retained demo preserve keys and private restart
        # commands. An explicit stop or a normal test run removes remote test state.
        preserve = bool(args.keep_running and failed and not explicit_stop)
        cleanup_errors = session.close(preserve=preserve) if session else []
        if temporary:
            temporary.cleanup()
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        os.umask(original_umask)
        for error in cleanup_errors:
            print("Cleanup attention required: " + error, file=sys.stderr)

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessError as error:
        print("Cross-device validation failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
