import json
import subprocess
from pathlib import Path

STATE_FILE = Path("/var/lib/proxmox-gateway/state.json")
MAPPINGS_FILE = Path("/var/lib/proxmox-gateway/mappings.json")

DNAT_CHAIN = "PROXMOX_GW_DNAT"
FWD_CHAIN = "PROXMOX_GW_FWD"
SNAT_CHAIN = "PROXMOX_GW_SNAT"


def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def iptables(*args, check=True):
    return subprocess.run(
        ["iptables", *args],
        text=True,
        capture_output=True,
        check=check,
    )


def ensure_chain(table, chain, parent):
    exists = iptables(
        "-t", table,
        "-L", chain,
        check=False,
    ).returncode == 0

    if not exists:
        iptables("-t", table, "-N", chain)

    connected = iptables(
        "-t", table,
        "-C", parent,
        "-j", chain,
        check=False,
    ).returncode == 0

    if not connected:
        iptables(
            "-t", table,
            "-I", parent,
            "1",
            "-j", chain,
        )


def rebuild():
    state = load_json(STATE_FILE, {})
    mappings = load_json(MAPPINGS_FILE, [])

    guests = {
        guest["name"]: guest
        for guest in state.values()
        if guest.get("ip")
    }

    active = []
    used = set()

    for mapping in mappings:
        guest = guests.get(mapping.get("guest"))

        if not guest:
            continue

        protocol = mapping["protocol"]
        external_port = int(mapping["external_port"])
        internal_port = int(mapping["internal_port"])

        key = (protocol, external_port)

        if key in used:
            continue

        used.add(key)

        active.append({
            **mapping,
            "ip": guest["ip"],
            "protocol": protocol,
            "external_port": external_port,
            "internal_port": internal_port,
        })

    ensure_chain("nat", DNAT_CHAIN, "PREROUTING")
    ensure_chain("filter", FWD_CHAIN, "FORWARD")
    ensure_chain("nat", SNAT_CHAIN, "POSTROUTING")

    iptables("-t", "nat", "-F", DNAT_CHAIN)
    iptables("-t", "filter", "-F", FWD_CHAIN)
    iptables("-t", "nat", "-F", SNAT_CHAIN)

    # Allow return traffic.
    iptables(
        "-t", "filter",
        "-A", FWD_CHAIN,
        "-m", "conntrack",
        "--ctstate", "ESTABLISHED,RELATED",
        "-j", "ACCEPT",
    )

    for mapping in active:
        protocol = mapping["protocol"]
        external = str(mapping["external_port"])
        internal = str(mapping["internal_port"])
        ip = mapping["ip"]

        # Internet -> guest
        iptables(
            "-t", "nat",
            "-A", DNAT_CHAIN,
            "-p", protocol,
            "--dport", external,
            "-j", "DNAT",
            "--to-destination",
            f"{ip}:{internal}",
        )

        # Allow forwarded connection.
        iptables(
            "-t", "filter",
            "-A", FWD_CHAIN,
            "-p", protocol,
            "-d", ip,
            "--dport", internal,
            "-m", "conntrack",
            "--ctstate", "NEW",
            "-j", "ACCEPT",
        )

        # Make return traffic come back through Oracle.
        iptables(
            "-t", "nat",
            "-A", SNAT_CHAIN,
            "-p", protocol,
            "-d", ip,
            "--dport", internal,
            "-j", "MASQUERADE",
        )

    return active
