#!/usr/bin/env python3

import hmac
import ipaddress
import json
import os
import re
import secrets
import subprocess
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

# ============================================================
# CONFIG
# ============================================================

BASE = Path("/opt/proxmox-gateway")
STATE_FILE = Path("/var/lib/proxmox-gateway/state.json")
MAPPINGS_FILE = Path("/var/lib/proxmox-gateway/mappings.json")
NGINX_ROUTES_FILE = Path("/var/lib/proxmox-gateway/nginx_routes.json")
NGINX_CONFIG_DIR = Path("/etc/nginx/proxmox-gateway")
NGINX_CONFIG_FILE = NGINX_CONFIG_DIR / "routes.conf"

ENV_FILE = BASE / ".env"

load_dotenv(ENV_FILE)

PASSWORD = os.getenv("WEBUI_PASSWORD")
SESSION_SECRET = os.getenv("WEBUI_SESSION_SECRET")
SSL_CERT = os.getenv("SSL_CERT")
SSL_KEY = os.getenv("SSL_KEY")
HOST = os.getenv("WEBUI_HOST", "0.0.0.0")
PORT = int(os.getenv("WEBUI_PORT", "5000"))

if not PASSWORD:
    raise SystemExit(
        "WEBUI_PASSWORD is not set in /opt/proxmox-gateway/.env"
    )

if not SESSION_SECRET:
    raise SystemExit(
        "WEBUI_SESSION_SECRET is not set in /opt/proxmox-gateway/.env"
    )

app = Flask(__name__)
app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

# ============================================================
# FILE HELPERS
# ============================================================


def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary = path.with_suffix(path.suffix + ".tmp")

    temporary.write_text(
        json.dumps(data, indent=2) + "\n"
    )

    temporary.replace(path)

    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass


# Make sure persistent files exist.
if not MAPPINGS_FILE.exists():
    save_json(MAPPINGS_FILE, [])

if not NGINX_ROUTES_FILE.exists():
    save_json(NGINX_ROUTES_FILE, [])

NGINX_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

if not NGINX_CONFIG_FILE.exists():
    NGINX_CONFIG_FILE.write_text(
        "# Proxmox Gateway managed Nginx routes.\n"
        "# Do not edit manually.\n"
    )

# ============================================================
# DISCOVERY
# ============================================================


def get_guests():
    state = load_json(STATE_FILE, {})

    guests = []

    for guest in state.values():
        if not isinstance(guest, dict):
            continue

        guests.append(guest)

    return sorted(
        guests,
        key=lambda guest: (
            guest.get("proxmox", ""),
            guest.get("name", ""),
        ),
    )


def get_guest(name):
    for guest in get_guests():
        if guest.get("name") == name:
            return guest

    return None


# ============================================================
# IPTABLES
# ============================================================

DNAT_CHAIN = "PROXMOX_GW_DNAT"
FWD_CHAIN = "PROXMOX_GW_FWD"
SNAT_CHAIN = "PROXMOX_GW_SNAT"


def get_mappings():
    return load_json(MAPPINGS_FILE, [])


def run_iptables(*args, check=True):
    return subprocess.run(
        ["iptables", *args],
        text=True,
        capture_output=True,
        check=check,
    )


def chain_exists(table, chain):
    return (
        run_iptables(
            "-t",
            table,
            "-L",
            chain,
            check=False,
        ).returncode
        == 0
    )


def ensure_chain(table, chain, parent):
    if not chain_exists(table, chain):
        run_iptables(
            "-t",
            table,
            "-N",
            chain,
        )

    connected = run_iptables(
        "-t",
        table,
        "-C",
        parent,
        "-j",
        chain,
        check=False,
    ).returncode == 0

    if not connected:
        run_iptables(
            "-t",
            table,
            "-I",
            parent,
            "1",
            "-j",
            chain,
        )


def rebuild_iptables():
    guests = {
        guest["name"]: guest
        for guest in get_guests()
        if guest.get("ip")
    }

    mappings = get_mappings()

    active = []
    used_ports = set()

    for mapping in mappings:
        guest_name = mapping.get("guest")
        guest = guests.get(guest_name)

        if not guest:
            continue

        protocol = mapping.get("protocol")

        if protocol not in {"tcp", "udp"}:
            continue

        external_port = int(mapping["external_port"])
        internal_port = int(mapping["internal_port"])

        key = (
            protocol,
            external_port,
        )

        if key in used_ports:
            continue

        used_ports.add(key)

        active.append(
            {
                **mapping,
                "guest": guest_name,
                "ip": guest["ip"],
                "protocol": protocol,
                "external_port": external_port,
                "internal_port": internal_port,
            }
        )

    ensure_chain(
        "nat",
        DNAT_CHAIN,
        "PREROUTING",
    )

    ensure_chain(
        "filter",
        FWD_CHAIN,
        "FORWARD",
    )

    ensure_chain(
        "nat",
        SNAT_CHAIN,
        "POSTROUTING",
    )

    run_iptables(
        "-t",
        "nat",
        "-F",
        DNAT_CHAIN,
    )

    run_iptables(
        "-t",
        "filter",
        "-F",
        FWD_CHAIN,
    )

    run_iptables(
        "-t",
        "nat",
        "-F",
        SNAT_CHAIN,
    )

    # Return traffic.
    run_iptables(
        "-t",
        "filter",
        "-A",
        FWD_CHAIN,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    )

    for mapping in active:
        protocol = mapping["protocol"]
        external_port = str(mapping["external_port"])
        internal_port = str(mapping["internal_port"])
        ip = mapping["ip"]

        # DNAT public port -> guest.
        run_iptables(
            "-t",
            "nat",
            "-A",
            DNAT_CHAIN,
            "-p",
            protocol,
            "--dport",
            external_port,
            "-j",
            "DNAT",
            "--to-destination",
            f"{ip}:{internal_port}",
        )

        # Allow forwarded connection.
        run_iptables(
            "-t",
            "filter",
            "-A",
            FWD_CHAIN,
            "-p",
            protocol,
            "-d",
            ip,
            "--dport",
            internal_port,
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-j",
            "ACCEPT",
        )

        # Make replies return through the gateway.
        run_iptables(
            "-t",
            "nat",
            "-A",
            SNAT_CHAIN,
            "-p",
            protocol,
            "-d",
            ip,
            "--dport",
            internal_port,
            "-j",
            "MASQUERADE",
        )

    return active


# ============================================================
# NGINX
# ============================================================


DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9.-]{0,251}"
    r"[a-zA-Z0-9])?$"
)


def validate_domain(domain):
    domain = domain.strip().lower()

    if not domain:
        raise ValueError("Domain is required.")

    if len(domain) > 253:
        raise ValueError("Domain is too long.")

    if domain == "_":
        raise ValueError("Invalid domain.")

    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Invalid domain.")

    if ".." in domain:
        raise ValueError("Invalid domain.")

    labels = domain.split(".")

    for label in labels:
        if not label:
            raise ValueError("Invalid domain.")

        if len(label) > 63:
            raise ValueError("Domain label is too long.")

        if label.startswith("-") or label.endswith("-"):
            raise ValueError("Invalid domain label.")

    return domain


def validate_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("Port must be a number.")

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    return port


def get_nginx_routes():
    return load_json(
        NGINX_ROUTES_FILE,
        [],
    )


def nginx_config_for_routes():
    guests = {
        guest["name"]: guest
        for guest in get_guests()
        if guest.get("ip")
    }

    routes = get_nginx_routes()

    active = []

    for route in routes:
        guest_name = route.get("guest")
        guest = guests.get(guest_name)

        if not guest:
            continue

        try:
            domain = validate_domain(
                route.get("domain", "")
            )

            port = validate_port(
                route.get("port")
            )

            ipaddress.ip_address(
                guest["ip"]
            )

        except ValueError:
            continue

        active.append(
            {
                **route,
                "domain": domain,
                "guest": guest_name,
                "ip": guest["ip"],
                "port": port,
            }
        )

    lines = [
        "# =====================================================",
        "# Managed by Proxmox Gateway",
        "# DO NOT EDIT THIS FILE MANUALLY",
        "# =====================================================",
        "",
    ]

    for route in active:
        domain = route["domain"]
        ip = route["ip"]
        port = route["port"]

        lines.extend(
        [
            "server {",
            "    listen 80;",
            f"    server_name {route['domain']};",
            "",
            "    return 301 https://$host$request_uri;",
            "}",
            "",
            "server {",
            "    listen 443 ssl;",
            f"    server_name {route['domain']};",
            "",
            f"    ssl_certificate {SSL_CERT};",
            f"    ssl_certificate_key {SSL_KEY};",
            "",
            "    location / {",
            f"        proxy_pass http://{route['ip']}:{route['port']};",
            "",
            "        proxy_http_version 1.1;",
            "        proxy_set_header Host $host;",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "        proxy_set_header Upgrade $http_upgrade;",
            '        proxy_set_header Connection "upgrade";',
            "        proxy_read_timeout 3600;",
            "        proxy_send_timeout 3600;",
            "    }",
            "}",
            "",
        ]
        )

    return "\n".join(lines), active


def nginx_test():
    result = subprocess.run(
        ["nginx", "-t"],
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stdout + result.stderr
        )


def reload_nginx():
    result = subprocess.run(
        [
            "systemctl",
            "reload",
            "nginx",
        ],
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stdout + result.stderr
        )


def rebuild_nginx():
    config, active = nginx_config_for_routes()

    old_config = ""

    if NGINX_CONFIG_FILE.exists():
        old_config = NGINX_CONFIG_FILE.read_text()

    # Always ensure the file exists.
    NGINX_CONFIG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    if config != old_config:
        # Write new configuration.
        NGINX_CONFIG_FILE.write_text(config)

        try:
            nginx_test()
        except Exception:
            # Restore previous working configuration.
            NGINX_CONFIG_FILE.write_text(
                old_config
            )
            raise

        reload_nginx()

    return active


# ============================================================
# AUTH
# ============================================================


def login_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(
                url_for(
                    "login",
                    next=request.path,
                )
            )

        return function(*args, **kwargs)

    return wrapped


def csrf_ok():
    expected = session.get("csrf", "")
    supplied = request.form.get("csrf", "")

    if not expected or not supplied:
        return False

    return hmac.compare_digest(
        supplied,
        expected,
    )


@app.after_request
def security_headers(response):
    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "same-origin"

    return response


# ============================================================
# HTML
# ============================================================

STYLE = """
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #111116;
    color: #e8e8ee;
    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

a {
    color: inherit;
}

.container {
    width: min(1400px, calc(100% - 32px));
    margin: 32px auto;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
}

h1 {
    margin: 0;
    font-size: 28px;
}

h2 {
    margin-top: 0;
    font-size: 20px;
}

.subtitle {
    color: #8e8e9a;
    margin-top: 5px;
}

.card {
    background: #19191f;
    border: 1px solid #2c2c35;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    text-align: left;
    padding: 12px 10px;
    border-bottom: 1px solid #2c2c35;
    white-space: nowrap;
}

th {
    color: #92929d;
    font-size: 13px;
    text-transform: uppercase;
}

td {
    font-size: 14px;
}

input,
select {
    background: #101015;
    border: 1px solid #35353f;
    color: #eeeef2;
    border-radius: 8px;
    padding: 10px 12px;
    min-width: 0;
}

button {
    border: 0;
    border-radius: 8px;
    padding: 10px 14px;
    cursor: pointer;
    background: #6d6aff;
    color: white;
    font-weight: 600;
}

button.danger {
    background: #8e3030;
}

button.secondary {
    background: #30303a;
}

form {
    margin: 0;
}

.form-grid {
    display: grid;
    grid-template-columns:
        minmax(180px, 1fr)
        minmax(180px, 1fr)
        120px
        auto;

    gap: 10px;
    margin-bottom: 20px;
}

.alert {
    padding: 12px 14px;
    border-radius: 8px;
    margin-bottom: 12px;
    background: #292930;
}

.alert.success {
    border: 1px solid #315c42;
}

.alert.error {
    border: 1px solid #713838;
}

.badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 6px;
    background: #292930;
    font-size: 12px;
}

.ip {
    font-family: monospace;
}

.empty {
    color: #777783;
    padding: 20px 0;
}

.login {
    width: min(420px, calc(100% - 32px));
    margin: 100px auto;
}

.login form {
    display: grid;
    gap: 12px;
}

.logout {
    display: inline;
}

@media (max-width: 800px) {
    .form-grid {
        grid-template-columns: 1fr;
    }

    header {
        align-items: flex-start;
        gap: 15px;
        flex-direction: column;
    }
}
"""


LOGIN_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Proxmox Gateway</title>
    <style>{{ style|safe }}</style>
</head>

<body>

<div class="login">
    <div class="card">

        <h1>Proxmox Gateway</h1>

        <p class="subtitle">
            Gateway management
        </p>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% for category, message in messages %}
                <div class="alert {{ category }}">
                    {{ message }}
                </div>
            {% endfor %}
        {% endwith %}

        <form method="post">

            <input
                type="password"
                name="password"
                placeholder="Password"
                autofocus
                required
            >

            <input
                type="hidden"
                name="csrf"
                value="{{ csrf }}"
            >

            <button type="submit">
                Login
            </button>

        </form>

    </div>
</div>

</body>
</html>
"""


INDEX_HTML = """
<!doctype html>

<html>

<head>

    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>Proxmox Gateway</title>

    <style>
        {{ style|safe }}
    </style>

</head>

<body>

<div class="container">

<header>

    <div>
        <h1>Proxmox Gateway</h1>

        <div class="subtitle">
            Proxmox discovery, TCP/UDP forwarding and Nginx routing
        </div>
    </div>

    <form
        method="post"
        action="{{ url_for('logout') }}"
    >
        <input
            type="hidden"
            name="csrf"
            value="{{ csrf }}"
        >

        <button class="secondary">
            Logout
        </button>
    </form>

</header>


{% with messages = get_flashed_messages(with_categories=true) %}

    {% for category, message in messages %}

        <div class="alert {{ category }}">
            {{ message }}
        </div>

    {% endfor %}

{% endwith %}


<!-- ===================================================== -->
<!-- GUESTS -->
<!-- ===================================================== -->

<div class="card">

    <h2>Discovered Guests</h2>

    {% if guests %}

    <table>

        <thead>
            <tr>
                <th>Name</th>
                <th>Proxmox</th>
                <th>Type</th>
                <th>Current IP</th>
            </tr>
        </thead>

        <tbody>

        {% for guest in guests %}

            <tr>

                <td>
                    <strong>
                        {{ guest.name }}
                    </strong>
                </td>

                <td>
                    <span class="badge">
                        {{ guest.proxmox }}
                    </span>
                </td>

                <td>
                    {{ guest.type or "unknown" }}
                </td>

                <td class="ip">
                    {{ guest.ip or "No IP" }}
                </td>

            </tr>

        {% endfor %}

        </tbody>

    </table>

    {% else %}

        <div class="empty">
            No guests discovered yet.
        </div>

    {% endif %}

</div>


<!-- ===================================================== -->
<!-- TCP / UDP -->
<!-- ===================================================== -->

<div class="card">

    <h2>TCP / UDP Port Forwarding</h2>

    <form
        method="post"
        action="{{ url_for('add_mapping') }}"
        class="form-grid"
    >

        <input
            type="hidden"
            name="csrf"
            value="{{ csrf }}"
        >

        <select name="guest" required>

            <option value="">
                Select guest
            </option>

            {% for guest in guests %}

                <option value="{{ guest.name }}">
                    {{ guest.name }}
                    — {{ guest.ip or "offline" }}
                </option>

            {% endfor %}

        </select>

        <select name="protocol" required>

            <option value="tcp">
                TCP
            </option>

            <option value="udp">
                UDP
            </option>

        </select>

        <input
            type="number"
            name="external_port"
            min="1"
            max="65535"
            placeholder="Public port"
            required
        >

        <input
            type="number"
            name="internal_port"
            min="1"
            max="65535"
            placeholder="Guest port"
            required
        >

        <button type="submit">
            Add Forward
        </button>

    </form>


    {% if mappings %}

    <table>

        <thead>

            <tr>
                <th>Guest</th>
                <th>Current IP</th>
                <th>Protocol</th>
                <th>Public Port</th>
                <th>Guest Port</th>
                <th></th>
            </tr>

        </thead>

        <tbody>

        {% for mapping in mappings %}

            <tr>

                <td>
                    {{ mapping.guest }}
                </td>

                <td class="ip">

                    {% if by_guest.get(mapping.guest) %}
                        {{ by_guest[mapping.guest].ip }}
                    {% else %}
                        offline
                    {% endif %}

                </td>

                <td>
                    <span class="badge">
                        {{ mapping.protocol.upper() }}
                    </span>
                </td>

                <td>
                    :{{ mapping.external_port }}
                </td>

                <td>
                    :{{ mapping.internal_port }}
                </td>

                <td>

                    <form
                        method="post"
                        action="{{ url_for(
                            'delete_mapping',
                            mapping_id=mapping.id
                        ) }}"
                    >

                        <input
                            type="hidden"
                            name="csrf"
                            value="{{ csrf }}"
                        >

                        <button
                            class="danger"
                            type="submit"
                        >
                            Delete
                        </button>

                    </form>

                </td>

            </tr>

        {% endfor %}

        </tbody>

    </table>

    {% else %}

        <div class="empty">
            No TCP/UDP forwards configured.
        </div>

    {% endif %}

</div>


<!-- ===================================================== -->
<!-- NGINX -->
<!-- ===================================================== -->

<div class="card">

    <h2>Nginx HTTP Routes</h2>

    <p class="subtitle">
        Map a DNS hostname to a port on a discovered VM or CT.
    </p>

    <form
        method="post"
        action="{{ url_for('add_nginx_route') }}"
        class="form-grid"
    >

        <input
            type="hidden"
            name="csrf"
            value="{{ csrf }}"
        >

        <input
            type="text"
            name="domain"
            placeholder="jellyfin.prox2.lon.jishnu.tech"
            required
        >

        <select name="guest" required>

            <option value="">
                Select guest
            </option>

            {% for guest in guests %}

                <option value="{{ guest.name }}">
                    {{ guest.name }}
                    — {{ guest.ip or "offline" }}
                </option>

            {% endfor %}

        </select>

        <input
            type="number"
            name="port"
            min="1"
            max="65535"
            placeholder="Port"
            required
        >

        <button type="submit">
            Add Route
        </button>

    </form>


    {% if nginx_routes %}

    <table>

        <thead>

            <tr>
                <th>Domain</th>
                <th>Guest</th>
                <th>Current IP</th>
                <th>Port</th>
                <th></th>
            </tr>

        </thead>

        <tbody>

        {% for route in nginx_routes %}

            <tr>

                <td>
                    <strong>
                        {{ route.domain }}
                    </strong>
                </td>

                <td>
                    {{ route.guest }}
                </td>

                <td class="ip">
                    {{ route.ip }}
                </td>

                <td>
                    :{{ route.port }}
                </td>

                <td>

                    <form
                        method="post"
                        action="{{ url_for(
                            'delete_nginx_route',
                            route_id=route.id
                        ) }}"
                    >

                        <input
                            type="hidden"
                            name="csrf"
                            value="{{ csrf }}"
                        >

                        <button
                            class="danger"
                            type="submit"
                        >
                            Delete
                        </button>

                    </form>

                </td>

            </tr>

        {% endfor %}

        </tbody>

    </table>

    {% else %}

        <div class="empty">
            No Nginx routes configured.
        </div>

    {% endif %}

</div>


<!-- ===================================================== -->
<!-- APPLY -->
<!-- ===================================================== -->

<div class="card">

    <form
        method="post"
        action="{{ url_for('apply_rules') }}"
    >

        <input
            type="hidden"
            name="csrf"
            value="{{ csrf }}"
        >

        <button class="secondary">
            Reapply All Forwarding Rules
        </button>

    </form>

</div>


</div>

</body>

</html>
"""


# ============================================================
# LOGIN
# ============================================================


@app.get("/login")
def login():
    if session.get("authenticated"):
        return redirect(url_for("index"))

    csrf = session.get("login_csrf")

    if not csrf:
        csrf = secrets.token_urlsafe(32)
        session["login_csrf"] = csrf

    return render_template_string(
        LOGIN_HTML,
        style=STYLE,
        csrf=csrf,
    )


@app.post("/login")
def login_post():
    supplied_password = request.form.get(
        "password",
        "",
    )

    supplied_csrf = request.form.get(
        "csrf",
        "",
    )

    expected_csrf = session.get(
        "login_csrf",
        "",
    )

    if not hmac.compare_digest(
        supplied_csrf,
        expected_csrf,
    ):
        flash(
            "Invalid login request.",
            "error",
        )

        return redirect(
            url_for("login")
        )

    if hmac.compare_digest(
        supplied_password,
        PASSWORD,
    ):
        session.clear()

        session["authenticated"] = True
        session["csrf"] = secrets.token_urlsafe(32)

        return redirect(
            url_for("index")
        )

    flash(
        "Invalid password.",
        "error",
    )

    return redirect(
        url_for("login")
    )


@app.post("/logout")
@login_required
def logout():
    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# MAIN PAGE
# ============================================================


@app.get("/")
@login_required
def index():
    current_guests = get_guests()
    current_mappings = get_mappings()

    by_guest = {
        guest["name"]: guest
        for guest in current_guests
    }

    nginx_routes = get_nginx_routes()

    # Add current IP to Nginx routes for display.
    display_routes = []

    for route in nginx_routes:
        route = dict(route)

        guest = by_guest.get(
            route.get("guest")
        )

        route["ip"] = (
            guest.get("ip")
            if guest
            else "offline"
        )

        display_routes.append(route)

    return render_template_string(
        INDEX_HTML,
        style=STYLE,
        guests=current_guests,
        mappings=current_mappings,
        nginx_routes=display_routes,
        by_guest=by_guest,
        csrf=session["csrf"],
    )


# ============================================================
# TCP / UDP ROUTES
# ============================================================


@app.post("/mappings/add")
@login_required
def add_mapping():
    if not csrf_ok():
        return (
            "CSRF validation failed",
            400,
        )

    guest_name = request.form.get(
        "guest",
        "",
    )

    protocol = request.form.get(
        "protocol",
        "",
    ).lower()

    try:
        external_port = validate_port(
            request.form.get(
                "external_port"
            )
        )

        internal_port = validate_port(
            request.form.get(
                "internal_port"
            )
        )

    except ValueError as exc:
        flash(
            str(exc),
            "error",
        )

        return redirect(
            url_for("index")
        )

    if protocol not in {"tcp", "udp"}:
        flash(
            "Protocol must be TCP or UDP.",
            "error",
        )

        return redirect(
            url_for("index")
        )

    guest = get_guest(
        guest_name
    )

    if not guest:
        flash(
            "Guest was not found.",
            "error",
        )

        return redirect(
            url_for("index")
        )

    mappings = get_mappings()

    duplicate = any(
        mapping.get("protocol") == protocol
        and int(
            mapping.get("external_port")
        ) == external_port
        for mapping in mappings
    )

    if duplicate:
        flash(
            f"{protocol.upper()} port "
            f"{external_port} is already "
            "assigned.",
            "error",
        )

        return redirect(
            url_for("index")
        )

    mappings.append(
        {
            "id": secrets.token_hex(8),
            "guest": guest_name,
            "protocol": protocol,
            "external_port": external_port,
            "internal_port": internal_port,
        }
    )

    save_json(
        MAPPINGS_FILE,
        mappings,
    )

    try:
        rebuild_iptables()

        flash(
            f"Added {protocol.upper()} "
            f":{external_port} → "
            f"{guest['ip']}:"
            f"{internal_port}",
            "success",
        )

    except Exception as exc:
        flash(
            f"iptables error: {exc}",
            "error",
        )

    return redirect(
        url_for("index")
    )


@app.post("/mappings/delete/<mapping_id>")
@login_required
def delete_mapping(mapping_id):
    if not csrf_ok():
        return (
            "CSRF validation failed",
            400,
        )

    mappings = get_mappings()

    new_mappings = [
        mapping
        for mapping in mappings
        if mapping.get("id") != mapping_id
    ]

    if len(new_mappings) == len(mappings):
        flash(
            "Mapping not found.",
            "error",
        )

    else:
        save_json(
            MAPPINGS_FILE,
            new_mappings,
        )

        try:
            rebuild_iptables()

            flash(
                "Forward removed.",
                "success",
            )

        except Exception as exc:
            flash(
                f"iptables error: {exc}",
                "error",
            )

    return redirect(
        url_for("index")
    )


# ============================================================
# NGINX ROUTES
# ============================================================


@app.post("/nginx/add")
@login_required
def add_nginx_route():
    if not csrf_ok():
        return (
            "CSRF validation failed",
            400,
        )

    try:
        domain = validate_domain(
            request.form.get(
                "domain",
                "",
            )
        )

        port = validate_port(
            request.form.get(
                "port"
            )
        )

    except ValueError as exc:
        flash(
            str(exc),
            "error",
        )

        return redirect(
            url_for("index")
        )

    guest_name = request.form.get(
        "guest",
        "",
    )

    guest = get_guest(
        guest_name
    )

    if not guest:
        flash(
            "Guest was not found.",
            "error",
        )

        return redirect(
            url_for("index")
        )

    routes = get_nginx_routes()

    duplicate = any(
        route.get("domain", "").lower()
        == domain
        for route in routes
    )

    if duplicate:
        flash(
            f"{domain} is already configured.",
            "error",
        )

        return redirect(
            url_for("index")
        )

    routes.append(
        {
            "id": secrets.token_hex(8),
            "domain": domain,
            "guest": guest_name,
            "port": port,
        }
    )

    save_json(
        NGINX_ROUTES_FILE,
        routes,
    )

    try:
        active = rebuild_nginx()

        flash(
            f"Added {domain} → "
            f"{guest['ip']}:{port}. "
            f"{len(active)} route(s) active.",
            "success",
        )

    except Exception as exc:
        # Remove the route if the generated
        # Nginx configuration could not be applied.
        routes = [
            route
            for route in routes
            if route.get("domain") != domain
        ]

        save_json(
            NGINX_ROUTES_FILE,
            routes,
        )

        flash(
            f"Nginx error: {exc}",
            "error",
        )

    return redirect(
        url_for("index")
    )


@app.post("/nginx/delete/<route_id>")
@login_required
def delete_nginx_route(route_id):
    if not csrf_ok():
        return (
            "CSRF validation failed",
            400,
        )

    routes = get_nginx_routes()

    new_routes = [
        route
        for route in routes
        if route.get("id") != route_id
    ]

    if len(new_routes) == len(routes):
        flash(
            "Nginx route not found.",
            "error",
        )

        return redirect(
            url_for("index")
        )

    save_json(
        NGINX_ROUTES_FILE,
        new_routes,
    )

    try:
        rebuild_nginx()

        flash(
            "Nginx route removed.",
            "success",
        )

    except Exception as exc:
        flash(
            f"Nginx error: {exc}",
            "error",
        )

    return redirect(
        url_for("index")
    )


# ============================================================
# MANUAL APPLY
# ============================================================


@app.post("/apply")
@login_required
def apply_rules():
    if not csrf_ok():
        return (
            "CSRF validation failed",
            400,
        )

    errors = []

    try:
        active = rebuild_iptables()

        flash(
            f"Applied {len(active)} "
            "TCP/UDP forwarding rule(s).",
            "success",
        )

    except Exception as exc:
        errors.append(
            f"iptables: {exc}"
        )

    try:
        active_nginx = rebuild_nginx()

        flash(
            f"Applied {len(active_nginx)} "
            "Nginx route(s).",
            "success",
        )

    except Exception as exc:
        errors.append(
            f"Nginx: {exc}"
        )

    for error in errors:
        flash(
            error,
            "error",
        )

    return redirect(
        url_for("index")
    )


# ============================================================
# START
# ============================================================


if __name__ == "__main__":
    app.run(
        host=HOST,
        port=PORT,
        debug=False,
    )
