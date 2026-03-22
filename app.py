#!/usr/bin/env python3
import os
import sys
import subprocess
import re
from pathlib import Path
from InquirerPy import inquirer
from InquirerPy.base import Choice

SITES_AVAILABLE = Path("/etc/nginx/sites-available")
SITES_ENABLED = Path("/etc/nginx/sites-enabled")


# ---------- Core helpers ----------

def run_sudo(cmd):
    subprocess.run(["sudo"] + cmd, check=True)


class NPMTransaction:
    """Track changes for rollback on failure."""
    def __init__(self):
        self.created_files = []     # new configs in sites-available
        self.created_symlinks = []  # new symlinks in sites-enabled
        self.old_files = {}         # {new_path: backup_path} for edits

    def add_file(self, path: Path):
        if path not in self.created_files:
            self.created_files.append(path)

    def add_symlink(self, path: Path):
        if path not in self.created_symlinks:
            self.created_symlinks.append(path)

    def backup_file(self, original: Path, backup: Path):
        self.old_files[original] = backup

    def rollback(self):
        print("🔄 Rolling back changes...")
        for ln in self.created_symlinks:
            if ln.exists():
                ln.unlink()
                print(f"  Removed symlink: {ln}")
        for f in self.created_files:
            if f.exists():
                f.unlink()
                print(f"  Removed file: {f}")
        for new_path, backup in self.old_files.items():
            if backup.exists():
                if new_path.exists():
                    new_path.unlink()
                backup.rename(new_path)
                print(f"  Restored backup: {new_path}")
        print("✅ Rollback complete.")


txn = NPMTransaction()


def safe_nginx_test():
    """Run nginx -t with Retry / Quit and rollback on quit."""
    while True:
        try:
            run_sudo(["nginx", "-t", "-q"])
            return
        except subprocess.CalledProcessError:
            action = inquirer.select(
                message="❌ nginx -t failed",
                choices=["retry", "quit"],
                default="retry",
            ).execute()
            if action == "quit":
                txn.rollback()
                sys.exit(1)


def safe_certbot(cmd):
    """Run certbot with Retry / Quit and rollback on quit."""
    while True:
        try:
            run_sudo(cmd)
            return
        except subprocess.CalledProcessError:
            action = inquirer.select(
                message="❌ certbot failed",
                choices=["retry", "quit"],
                default="retry",
            ).execute()
            if action == "quit":
                txn.rollback()
                sys.exit(1)


def certbot_register(email: str):
    """Try to register Certbot account once; ignore if it fails."""
    if not email:
        return
    try:
        run_sudo(["certbot", "register", "--email", email, "--agree-tos", "--non-interactive"])
        print(f"✅ Certbot account registered for {email}")
    except subprocess.CalledProcessError:
        print("ℹ️  Certbot already registered or registration skipped")


# ---------- Nginx config discovery ----------

def get_configs():
    if not SITES_AVAILABLE.exists():
        return []
    avail = [f for f in SITES_AVAILABLE.iterdir() if f.suffix == ".conf"]
    enabled_set = set()
    if SITES_ENABLED.exists():
        for link_path in SITES_ENABLED.iterdir():
            if link_path.is_symlink():
                target = link_path.resolve().name
                enabled_set.add(target)
    choices = []
    for conf in sorted(avail, key=lambda x: x.name):
        name = conf.name
        enabled = name in enabled_set
        label = f"{name} {'●' if enabled else '○'}"
        choices.append(Choice(value=name, name=label))
    return choices


def parse_proxy_pass(content: str):
    matches = re.findall(r"proxy_pass\s+([^\s;]+)", content)
    return [m.strip(" ;") for m in matches if "://" in m]


def get_all_targets():
    targets = set()
    if SITES_AVAILABLE.exists():
        for conf in SITES_AVAILABLE.glob("*.conf"):
            try:
                targets.update(parse_proxy_pass(conf.read_text()))
            except Exception:
                pass
    return sorted(targets)


def parse_config(path: Path):
    """Extract basic info from an existing config."""
    try:
        content = path.read_text()
        proxy_to = parse_proxy_pass(content)
        server_name_match = re.search(r"server_name\s+([^\s;]+)", content)
        server_name = server_name_match.group(1).strip() if server_name_match else ""

        websocket = "Upgrade $http_upgrade" in content
        ssl = False  # we no longer embed ssl blocks here, certbot manages them

        proxy_host_port = ""
        if proxy_to:
            full = proxy_to[0]
            if "://" in full:
                proxy_host_port = full.split("://", 1)[1]
            else:
                proxy_host_port = full

        if ":" in proxy_host_port:
            proxy_host, proxy_port = proxy_host_port.rsplit(":", 1)
        else:
            proxy_host, proxy_port = proxy_host_port, "80"

        proxy_type = "tcp" if (proxy_to and "tcp://" in proxy_to[0]) else "http"

        return {
            "server_name": server_name,
            "proxy_type": proxy_type,
            "proxy_host": proxy_host,
            "proxy_port": int(proxy_port) if proxy_port.isdigit() else 80,
            "websocket": websocket,
            "ssl": ssl,
        }
    except Exception:
        return {
            "server_name": "",
            "proxy_type": "http",
            "proxy_host": "localhost",
            "proxy_port": 80,
            "websocket": False,
            "ssl": False,
        }


# ---------- Template generation (HTTP-only, no SSL block) ----------

def create_config(server_name, proxy_host, proxy_port, websocket=False, proxy_type="http"):
    """
    Generate HTTP-only server block.
    No listen 443, no ssl_* directives.
    Certbot nginx plugin will modify this for HTTPS itself.
    """
    proxy_to = f"{proxy_host}:{proxy_port}"
    scheme = "http" if proxy_type == "http" else "tcp"

    lines = [
        "server {",
        "    listen 80;",
        f"    server_name {server_name};",
        "",
        "    location / {",
        f"        proxy_pass {scheme}://{proxy_to};",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
    ]

    if websocket:
        lines += [
            "        proxy_http_version 1.1;",
            "        proxy_set_header Upgrade $http_upgrade;",
            "        proxy_set_header Connection \"upgrade\";",
            "        proxy_read_timeout 3600s;",
            "        proxy_send_timeout 3600s;",
        ]

    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def validate_proxy_host(value: str):
    if value.startswith("http://") or value.startswith("tcp://"):
        return "❌ Do not enter http:// or tcp:// – only host or host:port"
    if not value:
        return "❌ Host is required"
    return True


# ---------- Operations ----------

def toggle_site(name: str):
    dst = SITES_ENABLED / name
    if dst.exists():
        dst.unlink()
        print(f"Disabled {name}")
    else:
        src = SITES_AVAILABLE / name
        run_sudo(["ln", "-s", str(src), str(dst)])
        txn.add_symlink(dst)
        print(f"Enabled {name}")
    safe_nginx_test()


def delete_site(name: str):
    dst = SITES_ENABLED / name
    if dst.exists():
        dst.unlink()
        print(f"Removed symlink {name}")

    path = SITES_AVAILABLE / name
    if path.exists():
        path.unlink()
        print(f"Deleted {name}")

    safe_nginx_test()


def manage():
    while True:
        configs = get_configs()
        if not configs:
            print("No .conf files in sites-available")
            return

        choice = inquirer.select(
            message="Manage sites:",
            choices=configs + [Choice(value="quit", name="❌ Quit")],
            default=configs[0] if configs else None,
            instruction="↑↓ Enter to toggle",
        ).execute()

        if choice == "quit":
            break
        toggle_site(choice)


def create():
    targets = get_all_targets()

    proxy_type = inquirer.select(
        message="Proxy Type:",
        choices=["http", "tcp"],
        default="http",
    ).execute()

    websocket = inquirer.confirm(
        message="Enable WebSocket support?",
        default=False,
    ).execute()

    ssl = inquirer.confirm(  # controls certbot only
        message="Request SSL with Certbot? (config remains HTTP-only)",
        default=False,
    ).execute()

    proxy_host = inquirer.text(
        message=f"Proxy host (suggestions: {', '.join(targets[:3])}):",
        default="localhost",
        validate=validate_proxy_host,
    ).execute()

    proxy_port = inquirer.number(
        message="Proxy port:",
        default=80,
        min_allowed=1,
        max_allowed=65535,
    ).execute()

    server_name = inquirer.text(
        message="Server name (domain):",
        validate=lambda x: "." in x and len(x) > 3,
    ).execute()

    email = ""
    if ssl:
        email = inquirer.text(message="Let’s Encrypt email:").execute()
        certbot_register(email)

    domain_clean = re.sub(r"^(https?://)?(www\.)?", "", server_name).strip().rstrip("/")
    conf_name = f"{domain_clean}.conf"
    conf_path = SITES_AVAILABLE / conf_name

    conf_text = create_config(
        server_name,
        proxy_host,
        proxy_port,
        websocket=websocket,
        proxy_type=proxy_type,
    )
    conf_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path.write_text(conf_text)
    txn.add_file(conf_path)

    # Symlink first, then certbot
    toggle_site(conf_name)

    if ssl:
        domains = [server_name]
        cmd = ["certbot", "--nginx", "--non-interactive", "--agree-tos"]
        for d in domains:
            cmd += ["-d", d]
        safe_certbot(cmd)

    print(f"✅ Created & enabled {conf_name}")


def edit_config(path: Path):
    current = parse_config(path)
    new = inquirer.prompt([
        inquirer.text(
            "server_name",
            message="Server name:",
            default=current["server_name"],
            validate=lambda x: "." in x and len(x) > 3,
        ),
        inquirer.select(
            "proxy_type",
            message="Proxy type:",
            choices=["http", "tcp"],
            default=current["proxy_type"],
        ),
        inquirer.confirm("websocket", message="WebSocket support?", default=current["websocket"]),
        inquirer.confirm(
            "ssl",
            message="Request SSL with Certbot? (config stays HTTP-only)",
            default=False,
        ),
        inquirer.text(
            "proxy_host",
            message="Proxy host:",
            default=current["proxy_host"],
            validate=validate_proxy_host,
        ),
        inquirer.number(
            "proxy_port",
            message="Proxy port:",
            default=current["proxy_port"],
            min_allowed=1,
            max_allowed=65535,
        ),
    ])
    if not new:
        print("Edit cancelled")
        return

    email = ""
    if new["ssl"]:
        email = inquirer.text(
            message="Let’s Encrypt email (Enter to skip):",
            default="",
        ).execute()
        if email:
            certbot_register(email)

    backup = path.with_suffix(".conf.backup")
    if path.exists():
        path.rename(backup)
        txn.backup_file(path, backup)

    domain_clean = re.sub(r"^(https?://)?(www\.)?", "", new["server_name"]).strip().rstrip("/")
    new_name = f"{domain_clean}.conf"
    new_path = SITES_AVAILABLE / new_name

    conf_text = create_config(
        new["server_name"],
        new["proxy_host"],
        new["proxy_port"],
        websocket=new["websocket"],
        proxy_type=new["proxy_type"],
    )
    new_path.write_text(conf_text)
    txn.add_file(new_path)

    toggle_site(new_name)

    if new["ssl"]:
        domains = [new["server_name"]]
        if not new["server_name"].startswith("www."):
            domains.append(f"www.{domain_clean}")
        cmd = ["certbot", "--nginx", "--non-interactive", "--agree-tos"]
        for d in domains:
            cmd += ["-d", d]
        safe_certbot(cmd)

    print(f"✅ Edited → {new_name}")


def edit():
    configs = get_configs()
    if not configs:
        print("No configs to edit")
        return

    name = inquirer.select(
        message="Select config to edit:",
        choices=configs,
    ).execute()

    if name:
        path = SITES_AVAILABLE / name
        if path.exists():
            edit_config(path)
        else:
            print("Config not found")


def delete():
    configs = get_configs()
    if not configs:
        print("No configs to delete")
        return

    name = inquirer.select(
        message="Select config to DELETE:",
        choices=configs,
        instruction="⚠️  Deletes file and symlink (no backup)",
    ).execute()

    if name:
        if inquirer.confirm(
            message=f"Delete {name} permanently?",
            default=False,
        ).execute():
            delete_site(name)


def main():
    if os.geteuid() != 0:
        print("Run with sudo to modify nginx configs.")
        return

    global txn
    txn = NPMTransaction()

    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
    else:
        cmd = inquirer.select(
            message="🚀 Nginx Proxy Manager",
            choices=["manage", "create", "edit", "delete", "quit"],
            default="manage",
        ).execute()

    if cmd == "manage":
        manage()
    elif cmd == "create":
        create()
    elif cmd == "edit":
        edit()
    elif cmd == "delete":
        delete()
    else:
        print("Goodbye")


if __name__ == "__main__":
    main()
