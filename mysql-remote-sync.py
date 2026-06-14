#!/usr/bin/env python3
import ipaddress
import json
import subprocess
import sys
import syslog
from pathlib import Path
from typing import List, Set

ZONE = "public"
PORT = 3306
STATE_FILE = Path("/var/lib/mysql-remote-sync/managed_rules.json")

RULE_TEMPLATE = 'rule family="ipv4" source address="{src}" port port="{port}" protocol="tcp" accept'


def run(cmd: List[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}"
        )
    return p.stdout


def get_accounts() -> List[str]:
    out = run(["whmapi1", "--output=jsonpretty", "listaccts"])
    data = json.loads(out)
    accounts = data.get("data", {}).get("acct", [])
    users = []

    for acct in accounts:
        user = acct.get("user")
        if user and user != "root":
            users.append(user)

    return sorted(set(users))


def get_remote_hosts_for_user(user: str) -> List[str]:
    out = run([
        "/usr/local/cpanel/bin/cpapi2",
        f"--user={user}",
        "--output=json",
        "MysqlFE",
        "listhosts"
    ])

    data = json.loads(out)
    rows = data.get("cpanelresult", {}).get("data", []) or []

    hosts = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        host = row.get("host") or row.get("uri_host")
        if host:
            hosts.append(host.strip())

    return hosts


def normalize_host_to_sources(host: str) -> List[str]:
    """
    MVP policy:
    - accept IPv4
    - accept IPv4 CIDR
    - ignore everything else (hostnames, wildcards, IPv6)
    """
    try:
        ip = ipaddress.IPv4Address(host)
        return [f"{ip}/32"]
    except Exception:
        pass

    try:
        net = ipaddress.IPv4Network(host, strict=False)
        return [str(net)]
    except Exception:
        pass

    return []


def desired_rules() -> Set[str]:
    rules = set()

    for user in get_accounts():
        try:
            hosts = get_remote_hosts_for_user(user)
        except Exception as e:
            print(f"[WARN] Could not read remote DB hosts for {user}: {e}", file=sys.stderr)
            syslog.syslog(syslog.LOG_WARNING, f"MYSQL-FW WARN failed to read remote DB hosts for {user}: {e}")
            continue

        for host in hosts:
            for src in normalize_host_to_sources(host):
                rules.add(RULE_TEMPLATE.format(src=src, port=PORT))

    return rules


def current_rich_rules() -> Set[str]:
    out = run(["firewall-cmd", "--permanent", "--zone", ZONE, "--list-rich-rules"])
    return {line.strip() for line in out.splitlines() if line.strip()}


def load_previous_managed_rules() -> Set[str]:
    if not STATE_FILE.exists():
        return set()
    return set(json.loads(STATE_FILE.read_text()))


def save_previous_managed_rules(rules: Set[str]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(sorted(rules), indent=2))


def add_rule(rule: str) -> None:
    run(["firewall-cmd", "--permanent", "--zone", ZONE, "--add-rich-rule", rule])


def remove_rule(rule: str) -> None:
    run(["firewall-cmd", "--permanent", "--zone", ZONE, "--remove-rich-rule", rule])


def main():
    apply_changes = "--apply" in sys.argv

    wanted = desired_rules()
    current = current_rich_rules()
    previous_managed = load_previous_managed_rules()

    to_add = sorted(wanted - current)
    to_remove = sorted((previous_managed & current) - wanted)

    print("[INFO] Desired rules:")
    for rule in sorted(wanted):
        print(f"  {rule}")

    print("\n[INFO] To add:")
    for rule in to_add:
        print(f"  {rule}")

    print("\n[INFO] To remove:")
    for rule in to_remove:
        print(f"  {rule}")

    if not apply_changes:
        print("\n[DRY-RUN] No changes applied. Re-run with --apply to enforce.")
        return

    changed = False

    for rule in to_add:
        print(f"[ADD] {rule}")
        syslog.syslog(syslog.LOG_WARNING, f"MYSQL-FW ADD {rule}")
        add_rule(rule)
        changed = True

    for rule in to_remove:
        print(f"[DEL] {rule}")
        syslog.syslog(syslog.LOG_WARNING, f"MYSQL-FW DEL {rule}")
        remove_rule(rule)
        changed = True

    if changed:
        run(["firewall-cmd", "--reload"])
        print("\n[OK] firewalld reloaded")
        syslog.syslog(syslog.LOG_WARNING, "MYSQL-FW firewalld reloaded after rule sync")
    else:
        print("\n[OK] no changes")
        syslog.syslog(syslog.LOG_INFO, "MYSQL-FW no changes")

    save_previous_managed_rules(wanted)


if __name__ == "__main__":
    main()
