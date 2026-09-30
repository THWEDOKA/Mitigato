#!/usr/bin/env python3
"""Mitigato: small Linux DDoS monitor and temporary nftables blocker."""

from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import logging
import os
from pathlib import Path
import shutil
import smtplib
import socket
import ssl
import struct
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage

VERSION = "0.1.0"
DEFAULT_CONFIG = Path("/etc/mitigato/config.toml")
INSTALLED_SCRIPT = Path("/usr/local/lib/mitigato/mitigato.py")
COMMAND_FILE = Path("/usr/local/bin/mitigato")
UNIT_FILE = Path("/etc/systemd/system/mitigato.service")
TABLE = "mitigato"
LOG = logging.getLogger("mitigato")


@dataclass(frozen=True)
class Config:
    interface: str = "auto"
    interval_seconds: int = 5
    alert_after_samples: int = 3
    recover_after_samples: int = 3
    alert_cooldown_seconds: int = 300
    packets_per_second: int = 10000
    bits_per_second: int = 100_000_000
    syn_recv_total: int = 500
    syn_recv_per_ip: int = 100
    firewall_enabled: bool = True
    block_seconds: int = 600
    max_blocks_per_cycle: int = 20
    trusted_ips: tuple[str, ...] = ()
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_security: str = "ssl"
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""


def load_config(path: Path) -> Config:
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    if set(data) - {"monitor", "firewall", "smtp", "telegram"}:
        raise ValueError("Unknown configuration section")
    groups = {name: data.get(name, {}) for name in ("monitor", "firewall", "smtp", "telegram")}
    if any(not isinstance(value, dict) for value in groups.values()):
        raise ValueError("Configuration sections must be tables")
    allowed = {
        "monitor": {"interface", "interval_seconds", "alert_after_samples", "recover_after_samples", "alert_cooldown_seconds", "packets_per_second", "bits_per_second", "syn_recv_total", "syn_recv_per_ip"},
        "firewall": {"enabled", "block_seconds", "max_blocks_per_cycle", "trusted_ips"},
        "smtp": {"host", "port", "security", "user", "password", "from", "to"},
        "telegram": {"bot_token", "chat_id"},
    }
    for name, group in groups.items():
        unknown = set(group) - allowed[name]
        if unknown:
            raise ValueError(f"Unknown {name} keys: {', '.join(sorted(unknown))}")
    m, f, s, t = (groups[name] for name in ("monitor", "firewall", "smtp", "telegram"))
    trusted_values = f.get("trusted_ips", [])
    if not isinstance(trusted_values, list) or any(not isinstance(item, str) for item in trusted_values):
        raise ValueError("firewall.trusted_ips must be a list of IP addresses or CIDRs")
    fields = {
        "interface": m.get("interface", "auto"),
        "interval_seconds": m.get("interval_seconds", 5),
        "alert_after_samples": m.get("alert_after_samples", 3),
        "recover_after_samples": m.get("recover_after_samples", 3),
        "alert_cooldown_seconds": m.get("alert_cooldown_seconds", 300),
        "packets_per_second": m.get("packets_per_second", 10000),
        "bits_per_second": m.get("bits_per_second", 100_000_000),
        "syn_recv_total": m.get("syn_recv_total", 500),
        "syn_recv_per_ip": m.get("syn_recv_per_ip", 100),
        "firewall_enabled": f.get("enabled", True),
        "block_seconds": f.get("block_seconds", 600),
        "max_blocks_per_cycle": f.get("max_blocks_per_cycle", 20),
        "trusted_ips": tuple(trusted_values),
        "smtp_host": s.get("host", ""),
        "smtp_port": s.get("port", 465),
        "smtp_security": s.get("security", "ssl"),
        "smtp_user": s.get("user", ""),
        "smtp_password": s.get("password", ""),
        "smtp_from": s.get("from", ""),
        "smtp_to": s.get("to", ""),
        "telegram_bot_token": t.get("bot_token", ""),
        "telegram_chat_id": t.get("chat_id", ""),
    }
    numeric = ("interval_seconds", "alert_after_samples", "recover_after_samples", "alert_cooldown_seconds", "packets_per_second", "bits_per_second", "syn_recv_total", "syn_recv_per_ip", "block_seconds", "max_blocks_per_cycle", "smtp_port")
    for key in numeric:
        value = fields[key]
        if type(value) is not int or value < (0 if key == "alert_cooldown_seconds" else 1):
            raise ValueError(f"{key} must be a positive integer" + (" or zero" if key == "alert_cooldown_seconds" else ""))
    if fields["smtp_port"] > 65535:
        raise ValueError("smtp_port must be at most 65535")
    for key, value in fields.items():
        if key in numeric or key == "trusted_ips":
            continue
        if key == "firewall_enabled":
            if type(value) is not bool:
                raise ValueError("firewall.enabled must be a boolean")
        elif not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
    for network in fields["trusted_ips"]:
        ipaddress.ip_network(network, strict=False)
    if fields["smtp_security"] not in ("ssl", "starttls"):
        raise ValueError("smtp.security must be ssl or starttls")
    if bool(fields["smtp_host"]) != bool(fields["smtp_to"]):
        raise ValueError("SMTP host and recipient must be configured together")
    if fields["smtp_host"] and not fields["smtp_from"]:
        raise ValueError("SMTP sender is required")
    if bool(fields["telegram_bot_token"]) != bool(fields["telegram_chat_id"]):
        raise ValueError("Telegram token and chat ID must be configured together")
    if not fields["smtp_host"] and not fields["telegram_bot_token"]:
        raise ValueError("Configure SMTP and/or Telegram for alerts")
    return Config(**fields)


def default_interface() -> str:
    with open("/proc/net/route", encoding="ascii") as stream:
        next(stream)
        for line in stream:
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "00000000" and int(parts[3], 16) & 1:
                return parts[0]
    with open("/proc/net/dev", encoding="ascii") as stream:
        names = [line.split(":", 1)[0].strip() for line in list(stream)[2:] if ":" in line]
    candidates = [name for name in names if name != "lo"]
    if not candidates:
        raise RuntimeError("No network interface found; set monitor.interface")
    return candidates[0]


def read_counters(interface: str) -> tuple[int, int]:
    with open("/proc/net/dev", encoding="ascii") as stream:
        for line in list(stream)[2:]:
            name, sep, values = line.partition(":")
            if sep and name.strip() == interface:
                columns = values.split()
                return int(columns[0]), int(columns[1])
    raise RuntimeError(f"Interface {interface!r} not found in /proc/net/dev")


def decode_remote_ip(raw: str, ipv6: bool) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if ipv6:
        octets = b"".join(struct.pack("<I", int(raw[i:i + 8], 16)) for i in range(0, 32, 8))
        return ipaddress.IPv6Address(octets)
    return ipaddress.IPv4Address(struct.pack("<I", int(raw, 16)))


def read_syn_recv() -> collections.Counter[str]:
    counts: collections.Counter[str] = collections.Counter()
    for filename, ipv6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        with open(filename, encoding="ascii") as stream:
            next(stream)
            for line in stream:
                parts = line.split()
                if len(parts) < 4 or parts[3] != "03":
                    continue
                raw_ip = parts[2].split(":", 1)[0]
                address = decode_remote_ip(raw_ip, ipv6)
                if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                    address = address.ipv4_mapped
                counts[str(address)] += 1
    return counts


def run_nft(*args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["nft", *args], input=input_text, text=True, capture_output=True, check=True, timeout=10)


def ensure_firewall() -> None:
    existing = subprocess.run(["nft", "list", "table", "inet", TABLE], text=True, capture_output=True, timeout=10)
    if existing.returncode == 0:
        if all(fragment in existing.stdout for fragment in ("set blocked_v4", "set blocked_v6", "chain input", "@blocked_v4", "@blocked_v6")):
            return
        raise RuntimeError("Existing nftables table 'mitigato' has an unexpected layout")
    rules = """table inet mitigato {
    set blocked_v4 { type ipv4_addr; flags timeout; }
    set blocked_v6 { type ipv6_addr; flags timeout; }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @blocked_v4 counter drop
        ip6 saddr @blocked_v6 counter drop
    }
}
"""
    run_nft("-f", "-", input_text=rules)


def remove_firewall() -> None:
    result = subprocess.run(["nft", "list", "table", "inet", TABLE], capture_output=True, text=True, timeout=10)
    if result.returncode == 0:
        if not all(fragment in result.stdout for fragment in ("set blocked_v4", "set blocked_v6", "chain input", "@blocked_v4", "@blocked_v6")):
            raise RuntimeError("Refusing to remove unexpected nftables table 'mitigato'")
        run_nft("delete", "table", "inet", TABLE)


def block_ip(address: str, seconds: int) -> None:
    ip = ipaddress.ip_address(address)
    set_name = "blocked_v4" if ip.version == 4 else "blocked_v6"
    run_nft("add", "element", "inet", TABLE, set_name, "{", str(ip), "timeout", f"{seconds}s", "}")


def is_blockable(address: str, trusted: tuple[ipaddress._BaseNetwork, ...]) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global and not ip.is_multicast and not any(ip in network for network in trusted)


def send_alert(config: Config, subject: str, message: str) -> bool:
    delivered = False
    all_succeeded = True
    if config.smtp_host:
        try:
            mail = EmailMessage()
            mail["Subject"] = subject
            mail["From"] = config.smtp_from
            mail["To"] = config.smtp_to
            mail.set_content(message)
            context = ssl.create_default_context()
            if config.smtp_security == "ssl":
                client = smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=10, context=context)
            else:
                client = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10)
            with client:
                if config.smtp_security == "starttls":
                    client.starttls(context=context)
                    client.ehlo()
                if config.smtp_user:
                    client.login(config.smtp_user, config.smtp_password)
                client.send_message(mail)
            LOG.info("SMTP alert sent")
            delivered = True
        except (OSError, ValueError, smtplib.SMTPException) as exc:
            LOG.error("SMTP delivery failed: %s", exc)
            all_succeeded = False
    if config.telegram_bot_token:
        try:
            endpoint = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"
            payload = urllib.parse.urlencode({"chat_id": config.telegram_chat_id, "text": f"{subject}\n\n{message}"}).encode()
            request = urllib.request.Request(endpoint, data=payload, method="POST")
            with urllib.request.urlopen(request, timeout=10) as response:
                data = json.load(response)
            if not data.get("ok"):
                raise RuntimeError("Telegram API returned ok=false")
            LOG.info("Telegram alert sent")
            delivered = True
        except urllib.error.HTTPError as exc:
            LOG.error("Telegram delivery failed: HTTP %s", exc.code)
            all_succeeded = False
        except (OSError, urllib.error.URLError, ValueError, RuntimeError) as exc:
            # urllib errors may contain the bot token in their URL.
            LOG.error("Telegram delivery failed: %s", type(exc).__name__)
            all_succeeded = False
    return delivered and all_succeeded


def format_metrics(pps: float, bps: float, counts: collections.Counter[str], reasons: list[str]) -> str:
    return (f"Host: {socket.gethostname()}\n"
            f"Reasons: {', '.join(reasons) if reasons else 'none'}\n"
            f"Inbound: {pps:,.0f} packets/s, {bps / 1_000_000:,.1f} Mbit/s\n"
            f"SYN_RECV: {sum(counts.values())}\n"
            f"Top sources: {', '.join(f'{ip} ({count})' for ip, count in counts.most_common(5)) or 'none'}")


def monitor(config: Config, *, once: bool = False, no_firewall: bool = False) -> None:
    interface = default_interface() if config.interface == "auto" else config.interface
    bytes_in, packets_in = read_counters(interface)
    last_time = time.monotonic()
    hit_samples = clear_samples = 0
    active = False
    last_alert = 0.0
    trusted = tuple(ipaddress.ip_network(value, strict=False) for value in config.trusted_ips)
    recent_blocks: dict[str, float] = {}
    if config.firewall_enabled and not no_firewall:
        ensure_firewall()
    last_firewall_check = last_time
    LOG.info("Monitoring %s every %ss", interface, config.interval_seconds)
    while True:
        time.sleep(config.interval_seconds)
        now = time.monotonic()
        if config.firewall_enabled and not no_firewall and now - last_firewall_check >= 60:
            ensure_firewall()
            last_firewall_check = now
        recent_blocks = {ip: expiry for ip, expiry in recent_blocks.items() if expiry > now}
        next_bytes, next_packets = read_counters(interface)
        elapsed = max(now - last_time, 0.001)
        if next_bytes < bytes_in or next_packets < packets_in:
            LOG.warning("Network counters reset; skipping sample")
            bytes_in, packets_in, last_time = next_bytes, next_packets, now
            if once:
                return
            continue
        pps = (next_packets - packets_in) / elapsed
        bps = 8 * (next_bytes - bytes_in) / elapsed
        bytes_in, packets_in, last_time = next_bytes, next_packets, now
        counts = read_syn_recv()
        reasons = []
        if pps >= config.packets_per_second:
            reasons.append("packet rate")
        if bps >= config.bits_per_second:
            reasons.append("bit rate")
        if sum(counts.values()) >= config.syn_recv_total:
            reasons.append("SYN_RECV total")
        if any(count >= config.syn_recv_per_ip for count in counts.values()):
            reasons.append("SYN_RECV per source")
        if config.firewall_enabled and not no_firewall:
            candidates = [(ip, count) for ip, count in counts.most_common() if count >= config.syn_recv_per_ip and is_blockable(ip, trusted)]
            for ip, count in candidates[:config.max_blocks_per_cycle]:
                if recent_blocks.get(ip, 0) > now:
                    continue
                try:
                    block_ip(ip, config.block_seconds)
                    recent_blocks[ip] = now + config.block_seconds
                    LOG.warning("Temporarily blocked %s (%s SYN_RECV sockets)", ip, count)
                except subprocess.CalledProcessError as exc:
                    if "File exists" in (exc.stderr or ""):
                        recent_blocks[ip] = now + config.block_seconds
                    else:
                        LOG.error("Could not block %s: %s", ip, exc)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    LOG.error("Could not block %s: %s", ip, exc)
        if reasons:
            hit_samples += 1
            clear_samples = 0
        else:
            clear_samples += 1
            hit_samples = 0
        if not active and hit_samples >= config.alert_after_samples:
            active = True
            last_alert = now
            LOG.warning("Possible DDoS attack detected: %s", ", ".join(reasons))
            send_alert(config, "Mitigato: possible DDoS attack", format_metrics(pps, bps, counts, reasons))
        elif active and not reasons and clear_samples >= config.recover_after_samples:
            active = False
            LOG.info("Traffic returned below configured thresholds")
            send_alert(config, "Mitigato: traffic recovered", format_metrics(pps, bps, counts, reasons))
        elif active and reasons and now - last_alert >= config.alert_cooldown_seconds:
            last_alert = now
            send_alert(config, "Mitigato: attack still active", format_metrics(pps, bps, counts, reasons))
        if once:
            LOG.info("Sample: %.0f packets/s, %.1f Mbit/s, %s SYN_RECV", pps, bps / 1_000_000, sum(counts.values()))
            return


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def prompt(label: str, default: str = "", *, secret: bool = False) -> str:
    from getpass import getpass
    suffix = f" [{default}]" if default else ""
    value = getpass(f"{label}{suffix}: ") if secret else input(f"{label}{suffix}: ")
    return (value if secret else value.strip()) or default


def create_config(path: Path) -> None:
    print("Mitigato setup. Press Enter to keep a default or leave an optional channel empty.")
    smtp_host = prompt("SMTP host (optional)")
    smtp_port = prompt("SMTP port", "465") if smtp_host else "465"
    smtp_security = prompt("SMTP security (ssl/starttls)", "ssl") if smtp_host else "ssl"
    smtp_user = prompt("SMTP username") if smtp_host else ""
    smtp_password = prompt("SMTP password", secret=True) if smtp_host else ""
    smtp_from = prompt("SMTP sender address") if smtp_host else ""
    smtp_to = prompt("Alert recipient email") if smtp_host else ""
    telegram_bot_token = prompt("Telegram bot token (optional)", secret=True)
    telegram_chat_id = prompt("Telegram chat ID") if telegram_bot_token else ""
    trusted = prompt("Trusted management IPs/CIDRs, comma-separated (optional)")
    if not smtp_host and not telegram_bot_token:
        raise ValueError("At least one alert channel is required")
    if any(char not in "0123456789" for char in smtp_port):
        raise ValueError("SMTP port must be numeric")
    trusted_ips = [value.strip() for value in trusted.split(",") if value.strip()]
    content = f'''# Mitigato configuration. Edit this file and restart mitigato.service.
[monitor]
interface = "auto"
interval_seconds = 5
alert_after_samples = 3
recover_after_samples = 3
alert_cooldown_seconds = 300
packets_per_second = 10000
bits_per_second = 100000000
syn_recv_total = 500
syn_recv_per_ip = 100

[firewall]
enabled = true
block_seconds = 600
max_blocks_per_cycle = 20
trusted_ips = [{", ".join(toml_string(ip) for ip in trusted_ips)}]

[smtp]
host = {toml_string(smtp_host)}
port = {smtp_port}
security = {toml_string(smtp_security)}
user = {toml_string(smtp_user)}
password = {toml_string(smtp_password)}
from = {toml_string(smtp_from)}
to = {toml_string(smtp_to)}

[telegram]
bot_token = {toml_string(telegram_bot_token)}
chat_id = {toml_string(telegram_chat_id)}
'''
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
    try:
        load_config(path)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def render_unit(python: Path, config_path: Path, nft_binary: str) -> str:
    return f'''[Unit]
Description=Mitigato server traffic monitor
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={python} {INSTALLED_SCRIPT} run --config {config_path}
ExecStopPost=-{nft_binary} delete table inet {TABLE}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
'''


def install(config_path: Path, reconfigure: bool = False) -> None:
    if os.geteuid() != 0:
        raise PermissionError("Run installation with sudo")
    if not shutil.which("nft") or not shutil.which("systemctl"):
        raise RuntimeError("Install nftables and systemd first")
    command_link = COMMAND_FILE
    marker = "# Managed by Mitigato installer\n"
    if command_link.exists() or command_link.is_symlink():
        if not (command_link.is_symlink() and command_link.resolve() == INSTALLED_SCRIPT):
            try:
                managed = command_link.is_file() and marker in command_link.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                managed = False
            if not managed:
                raise RuntimeError(f"Refusing to overwrite unrelated command: {command_link}")
    if reconfigure and config_path.exists():
        backup = config_path.with_name(config_path.name + ".bak")
        shutil.copy2(config_path, backup)
        os.chmod(backup, 0o600)
        config_path.unlink()
        print(f"Previous configuration saved to {backup}")
        try:
            create_config(config_path)
        except Exception:
            shutil.copy2(backup, config_path)
            os.chmod(config_path, 0o600)
            raise
    elif not config_path.exists():
        create_config(config_path)
    load_config(config_path)
    os.chmod(config_path, 0o600)
    python = Path(sys.executable)
    version = subprocess.run([str(python), "-c", "import tomllib"], capture_output=True)
    if version.returncode:
        raise RuntimeError(f"{python} needs Python 3.11 or newer")
    INSTALLED_SCRIPT.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if Path(__file__).resolve() != INSTALLED_SCRIPT.resolve():
        shutil.copy2(__file__, INSTALLED_SCRIPT)
    os.chmod(INSTALLED_SCRIPT, 0o755)
    nft_binary = shutil.which("nft")
    if any(" " in str(path) for path in (python, INSTALLED_SCRIPT, config_path, UNIT_FILE)):
        raise ValueError("Installation paths cannot contain spaces")
    unit = render_unit(python, config_path, nft_binary)
    UNIT_FILE.write_text(unit, encoding="utf-8")
    os.chmod(UNIT_FILE, 0o644)
    command_link.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if command_link.exists() or command_link.is_symlink():
        if command_link.is_symlink() and command_link.resolve() == INSTALLED_SCRIPT:
            command_link.unlink()
    command_link.write_text(f"#!/bin/sh\n{marker}exec {python} {INSTALLED_SCRIPT} \"$@\"\n", encoding="utf-8")
    os.chmod(command_link, 0o755)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "mitigato.service"], check=True)
    subprocess.run(["systemctl", "restart", "mitigato.service"], check=True)
    if subprocess.run(["systemctl", "is-active", "--quiet", "mitigato.service"]).returncode:
        raise RuntimeError("Mitigato service did not start; inspect journalctl -u mitigato.service")
    print(f"Mitigato installed. Config: {config_path}")
    print("Check: systemctl status mitigato.service")
    print("Send test alert: sudo mitigato test-alert")


def uninstall(purge: bool, config_path: Path) -> None:
    if os.geteuid() != 0:
        raise PermissionError("Run uninstall with sudo")
    stopped = subprocess.run(["systemctl", "disable", "--now", "mitigato.service"], check=False)
    if stopped.returncode and UNIT_FILE.exists():
        raise RuntimeError("Could not stop mitigato.service; refusing to remove a running installation")
    remove_firewall()
    UNIT_FILE.unlink(missing_ok=True)
    INSTALLED_SCRIPT.unlink(missing_ok=True)
    command_link = COMMAND_FILE
    if command_link.is_symlink() and command_link.resolve() == INSTALLED_SCRIPT:
        command_link.unlink()
    elif command_link.is_file() and "# Managed by Mitigato installer" in command_link.read_text(encoding="utf-8"):
        command_link.unlink()
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    if purge:
        config_path.unlink(missing_ok=True)
        config_path.with_name(config_path.name + ".bak").unlink(missing_ok=True)
        try:
            config_path.parent.rmdir()
        except OSError:
            pass
    print("Mitigato removed." + (" Configuration deleted." if purge else f" Configuration kept at {config_path}."))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mitigato Linux server DDoS monitor")
    parser.add_argument("--version", action="version", version=f"Mitigato {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "uninstall", "check", "run", "test-alert"):
        command = sub.add_parser(name)
        command.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
        if name == "install":
            command.add_argument("--reconfigure", action="store_true")
        if name == "uninstall":
            command.add_argument("--purge", action="store_true")
        if name == "run":
            command.add_argument("--once", action="store_true")
            command.add_argument("--no-firewall", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.command == "install":
            install(args.config, args.reconfigure)
        elif args.command == "uninstall":
            uninstall(args.purge, args.config)
        else:
            config = load_config(args.config)
            if args.command == "check":
                interface = default_interface() if config.interface == "auto" else config.interface
                read_counters(interface)
                read_syn_recv()
                print(f"Configuration OK. Interface: {interface}. Firewall: {'on' if config.firewall_enabled else 'off'}.")
            elif args.command == "test-alert":
                if not send_alert(config, "Mitigato: test alert", f"Test notification from {socket.gethostname()}"):
                    return 1
            elif args.command == "run":
                monitor(config, once=args.once, no_firewall=args.no_firewall)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, tomllib.TOMLDecodeError) as exc:
        LOG.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
