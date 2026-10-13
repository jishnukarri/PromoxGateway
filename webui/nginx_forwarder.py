import time

from nginx_manager import rebuild


last_state = None

while True:
    try:
        active = rebuild()

        state = tuple(
            sorted(
                (
                    route["id"],
                    route["domain"],
                    route["guest"],
                    route["ip"],
                    route["port"],
                )
                for route in active
            )
        )

        if state != last_state:
            print(
                f"[INFO] Applied {len(active)} Nginx routes",
                flush=True,
            )

            for route in active:
                print(
                    f"  {route['domain']} -> "
                    f"{route['ip']}:{route['port']}",
                    flush=True,
                )

            last_state = state

    except Exception as exc:
        print(f"[ERROR] {exc}", flush=True)

    time.sleep(5)
