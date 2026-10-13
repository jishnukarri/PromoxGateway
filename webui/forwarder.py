import time

from iptables_manager import rebuild


last_state = None

while True:
    try:
        active = rebuild()

        state = tuple(
            sorted(
                (
                    x["id"],
                    x["ip"],
                    x["protocol"],
                    x["external_port"],
                    x["internal_port"],
                )
                for x in active
            )
        )

        if state != last_state:
            print(
                f"[INFO] Applied {len(active)} forwarding rules",
                flush=True,
            )

            for rule in active:
                print(
                    f"  {rule['protocol'].upper()} "
                    f":{rule['external_port']} -> "
                    f"{rule['ip']}:{rule['internal_port']}",
                    flush=True,
                )

            last_state = state

    except Exception as exc:
        print(
            f"[ERROR] {exc}",
            flush=True,
        )

    time.sleep(5)
