#!/usr/bin/env python3
"""Pair the running Slipstream coordinator, then keep its inventory current."""

import getpass
import json
import re
import shlex
import subprocess
import sys


HOST = "root@slipstream.host"
ORIGIN = "https://nebula.parallax.link"
STATE = "/var/lib/parallax-nucleus-coordinator"
RELEASE = "11db01f"
BINARY = f"/opt/parallax/nucleus-account/{RELEASE}/nucleus"
SOURCE = f"/home/forge/.nebula-hosted/current/public/downloads/nucleus/{RELEASE}/nucleus-linux-amd64"
DIGEST = "58eafc08238c3f231dfefc04ef30b755f3bc23789dcb79228965252c8919eaee"
AS_OWNER = ("/usr/sbin/runuser", "-u", "nucleus-coordinator", "--", "env", f"NUCLEUS_HOME={STATE}")
UNIT = "parallax-cluster-report.service"


def ssh(*arguments, stdin=None, capture=False, check=True):
    return subprocess.run(
        ["ssh", "-T", "-o", "ConnectTimeout=8", HOST, shlex.join(arguments)],
        input=stdin, stdout=subprocess.PIPE if capture else None, text=True, check=check,
    )


def read_code():
    print(f'In {ORIGIN}/dashboard/connections, select your organization, name the cluster Slipstream,'
          ' then click “Create connection code” and “Copy command”.', flush=True)
    parts = shlex.split(getpass.getpass("Paste the copied command and press Enter (input is hidden): ").strip())
    if len(parts) == 7 and parts[:-1] == ["nucleus", "account", "connect", "--url", ORIGIN, "--code"]:
        parts = parts[-1:]
    if len(parts) != 1 or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.[0-9a-f]{64}", parts[0]):
        raise SystemExit("That did not match the connection command. Use Copy command in Your clusters and try again.")
    return parts[0]


STAGE_CONNECTOR = """
set -euo pipefail
source_file=$1
binary=$2
digest=$3
directory=$(dirname "$binary")
verify() { printf '%s  %s\\n' "$digest" "$1" | sha256sum --check --status; }
install -d -m 0755 "$directory"
if [[ -e "$binary" || -L "$binary" ]]; then
    [[ ! -L "$binary" && -f "$binary" ]] && verify "$binary" && exit 0
    echo 'The existing connector differs from the published build.' >&2
    exit 1
fi
staged=$(mktemp "$directory/.stage.XXXXXX")
trap 'unlink "$staged"' EXIT
cat "$source_file" > "$staged"
verify "$staged" || { echo 'Connector checksum mismatch.' >&2; exit 1; }
chmod 0755 "$staged"
ln "$staged" "$binary" || verify "$binary"
"""

ENABLE_REPORTER = """
set -euo pipefail
unit=$1
destination=/etc/systemd/system/$unit
staged=$(mktemp /etc/systemd/system/.parallax-cluster-report.XXXXXX)
trap 'unlink "$staged"' EXIT
cat > "$staged"
chmod 0644 "$staged"
existing=$(systemctl show "$unit" --property=FragmentPath --value)
if [[ -n "$existing" && "$existing" != "$destination" ]]; then
    echo "A reporting service already exists at $existing." >&2
    exit 1
fi
if ! ln "$staged" "$destination" 2>/dev/null; then
    cmp -s "$staged" "$destination" || { echo 'Existing reporting service has different settings.' >&2; exit 1; }
fi
systemctl daemon-reload
systemctl enable --now "$unit"
systemctl is-active --quiet "$unit"
"""

SERVICE = f"""[Unit]
Description=Report Slipstream cluster inventory to its Parallax account
After=network-online.target nucleus-coordinator.service
ConditionPathExists={STATE}/parallax-account.json

[Service]
User=nucleus-coordinator
WorkingDirectory={STATE}
Environment=NUCLEUS_HOME={STATE}
ExecStart={BINARY} account report
Restart=on-failure
RestartSec=15s
NoNewPrivileges=true
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def main():
    bound = ssh("test", "-e", f"{STATE}/parallax-account.json", check=False)
    if bound.returncode not in (0, 1):
        raise SystemExit("Could not reach Slipstream over SSH.")
    code = read_code() if bound.returncode == 1 else None
    ssh("/bin/bash", "-c", STAGE_CONNECTOR, "stage", SOURCE, BINARY, DIGEST)
    if code:
        # Pass the input through SSH stdin. The pasted text is never run as shell code.
        connect = 'IFS= read -r code && exec "$1" account connect --url "$2" --code "$code"'
        ssh(*AS_OWNER, "/bin/bash", "-c", connect, "connect", BINARY, ORIGIN, stdin=code + "\n")
    else:
        binding = json.loads(ssh(*AS_OWNER, BINARY, "account", "status", capture=True).stdout)
        if binding["origin"] != ORIGIN:
            raise SystemExit("The coordinator already has a binding to another account service.")
        print(f'Using the saved connection for {binding["name"]}.', flush=True)
    report = ssh(*AS_OWNER, BINARY, "account", "report", "--once", check=False)
    if report.returncode:
        raise SystemExit("The connection is saved. Run this helper again to retry the first inventory report.")
    ssh("/bin/bash", "-c", ENABLE_REPORTER, "enable", UNIT, stdin=SERVICE)
    print(f"First report accepted. Slipstream will keep reporting. Open {ORIGIN}/dashboard/connections.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        sys.exit("Input cancelled.")
    except ValueError:
        sys.exit("Could not read the connection information.")
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
