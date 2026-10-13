import os
import time
import json
from pathlib import Path

from dotenv import load_dotenv
import requests
import urllib3

load_dotenv("/opt/proxmox-gateway/.env")
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

STATE_FILE = Path("/var/lib/proxmox-gateway/state.json")


class Proxmox:
    def __init__(self, name, url, token_id, token_secret):
        self.name = name
        self.url = url.rstrip("/")

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "Authorization":
                f"PVEAPIToken={token_id}={token_secret}"
        })

    def get(self, path):
        response = self.session.get(
            f"{self.url}/api2/json{path}",
            timeout=10,
        )

        response.raise_for_status()
        return response.json()["data"]

    def get_guests(self):
        guests = []

        for node_info in self.get("/nodes"):
            node = node_info["node"]

            # LXC
            try:
                for guest in self.get(
                    f"/nodes/{node}/lxc"
                ):
                    if guest.get("status") != "running":
                        continue

                    guests.append({
                        "proxmox": self.name,
                        "node": node,
                        "vmid": int(guest["vmid"]),
                        "name": guest.get(
                            "name",
                            str(guest["vmid"])
                        ),
                        "type": "lxc",
                    })

            except Exception as e:
                print(
                    f"[ERROR] LXC discovery "
                    f"{self.name}/{node}: {e}"
                )

            # QEMU
            try:
                for guest in self.get(
                    f"/nodes/{node}/qemu"
                ):
                    if guest.get("status") != "running":
                        continue

                    guests.append({
                        "proxmox": self.name,
                        "node": node,
                        "vmid": int(guest["vmid"]),
                        "name": guest.get(
                            "name",
                            str(guest["vmid"])
                        ),
                        "type": "qemu",
                    })

            except Exception as e:
                print(
                    f"[ERROR] QEMU discovery "
                    f"{self.name}/{node}: {e}"
                )

        return guests

    def get_ip(self, guest):
        try:
            if guest["type"] == "lxc":
                interfaces = self.get(
                    f"/nodes/{guest['node']}/lxc/"
                    f"{guest['vmid']}/interfaces"
                )

                for interface in interfaces:
                    if interface.get("name") == "lo":
                        continue

                    for address in interface.get(
                        "ip-addresses", []
                    ):
                        ip = address.get("ip-address")

                        if (
                            ip
                            and "." in ip
                            and not ip.startswith("127.")
                        ):
                            return ip

            elif guest["type"] == "qemu":
                result = self.get(
                    f"/nodes/{guest['node']}/qemu/"
                    f"{guest['vmid']}/agent/"
                    f"network-get-interfaces"
                )

                for interface in result:
                    if interface.get("name") == "lo":
                        continue

                    for address in interface.get(
                        "ip-addresses", []
                    ):
                        ip = address.get("ip-address")

                        if (
                            ip
                            and "." in ip
                            and not ip.startswith("127.")
                        ):
                            return ip

        except Exception as e:
            print(
                f"[WARN] IP discovery failed for "
                f"{guest['name']}: {e}"
            )

        return None


def load_proxmox(prefix, name):
    url = os.getenv(f"{prefix}_URL")
    token_id = os.getenv(f"{prefix}_TOKEN_ID")
    token_secret = os.getenv(
        f"{prefix}_TOKEN_SECRET"
    )

    if not all([
        url,
        token_id,
        token_secret,
    ]):
        return None

    return Proxmox(
        name,
        url,
        token_id,
        token_secret,
    )


def main():
    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    interval = int(
        os.getenv("SCAN_INTERVAL", "10")
    )

    proxmox_servers = []

    for prefix, name in [
        ("PVE1", "prox1"),
        ("PVE2", "prox2"),
    ]:
        server = load_proxmox(
            prefix,
            name,
        )

        if server:
            proxmox_servers.append(server)

    while True:
        print("[INFO] Discovering Proxmox guests")

        state = {}

        for proxmox in proxmox_servers:
            try:
                guests = proxmox.get_guests()

                for guest in guests:
                    ip = proxmox.get_ip(guest)

                    if not ip:
                        print(
                            f"[WARN] No IP for "
                            f"{guest['name']}"
                        )
                        continue

                    hostname = (
                        f"{guest['name']}."
                        f"{proxmox.name}."
                        f"lon.jishnu.tech"
                    )

                    state[hostname] = {
                        **guest,
                        "ip": ip,
                    }

                    print(
                        f"[FOUND] "
                        f"{hostname} -> {ip}"
                    )

            except Exception as e:
                print(
                    f"[ERROR] {proxmox.name}: {e}"
                )

        temporary = STATE_FILE.with_suffix(
            ".tmp"
        )

        temporary.write_text(
            json.dumps(
                state,
                indent=2,
            )
        )

        temporary.replace(STATE_FILE)

        print(
            f"[INFO] {len(state)} guests discovered"
        )

        time.sleep(interval)


if __name__ == "__main__":
    main()
