#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY = {"OK": 0, "INFO": 1, "WARNING": 2, "HIGH": 3, "CRITICAL": 4}
DEFAULT_ROOT = Path.home() / "openclaw-monitor"
DEFAULT_PHASE1_ROOT = Path.home() / "openclaw-sentinel-phase1"


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return data


def _dig(data: Any, *path: str, default: Any = None) -> Any:
    cur = data
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _first(data: dict[str, Any], paths: list[tuple[str, ...]], default: Any = None) -> Any:
    for path in paths:
        value = _dig(data, *path, default=None)
        if value is not None:
            return value
    return default


def _as_bool(value: Any, default: bool | None = None) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "yes", "1", "up", "running", "active", "ok", "reachable"}:
            return True
        if v in {"false", "no", "0", "down", "stopped", "inactive", "failed", "unreachable"}:
            return False
    return default


def _as_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, str):
        value = value.strip().rstrip("%")
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _norm_mac(value: Any) -> str | None:
    if not value:
        return None
    return str(value).strip().lower().replace("-", ":")


def _normalize_devices(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("devices") or value.get("hosts") or value.get("entries") or []
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip") or item.get("address") or item.get("ipv4")
        mac = _norm_mac(item.get("mac") or item.get("mac_address"))
        hostname = item.get("hostname") or item.get("name")
        if ip or mac:
            out.append({"ip": ip, "mac": mac, "hostname": hostname})
    return sorted(out, key=lambda x: (x.get("mac") or "", x.get("ip") or ""))


def _split_local_endpoint(value: Any) -> tuple[str, int | None]:
    text = str(value or "").strip()
    if not text:
        return "*", None
    if text.startswith("[") and "]:" in text:
        address, port = text[1:].rsplit("]:" , 1)
    elif ":" in text:
        address, port = text.rsplit(":", 1)
    else:
        return text, None
    try:
        return address or "*", int(port)
    except ValueError:
        return address or "*", None


def _normalize_listeners(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("listeners") or value.get("sockets") or value.get("ports") or []
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        port = item.get("port") or item.get("local_port")
        address = item.get("address") or item.get("local_address")
        if port is None and item.get("local"):
            address, port = _split_local_endpoint(item.get("local"))
        if port is None:
            continue
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        raw = str(item.get("raw") or "")
        process = item.get("process") or item.get("program") or item.get("name")
        if not process and raw:
            m = re.search(r'users:\(\(\"([^\"]+)\"', raw)
            if m:
                process = m.group(1)
        out.append({
            "proto": str(item.get("proto") or item.get("protocol") or "tcp").lower(),
            "address": str(address or "*"),
            "port": port,
            "process": process,
        })
    return sorted(out, key=lambda x: (x["proto"], x["address"], x["port"]))


def _normalize_integrity(value: Any) -> dict[str, dict[str, Any]]:
    if isinstance(value, list):
        out = {}
        for item in value:
            if not isinstance(item, dict):
                continue
            path = item.get("path") or item.get("file")
            if path:
                out[str(path)] = {"sha256": item.get("sha256") or item.get("hash")}
        return out
    if isinstance(value, dict):
        out = {}
        for path, item in value.items():
            if isinstance(item, dict):
                out[str(path)] = {"sha256": item.get("sha256") or item.get("hash")}
            elif isinstance(item, str):
                out[str(path)] = {"sha256": item}
        return out
    return {}


def _raw_path(report_path: Path | None, relative: Any) -> Path | None:
    if report_path is None or not relative:
        return None
    p = Path(str(relative))
    return p if p.is_absolute() else report_path.parent / p


def _read_raw(report_path: Path | None, relative: Any) -> str:
    p = _raw_path(report_path, relative)
    if p is None or not p.exists() or not p.is_file():
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _parse_ip_neigh(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        try:
            idx = parts.index("lladdr")
        except ValueError:
            continue
        if idx + 1 < len(parts):
            mac = _norm_mac(parts[idx + 1])
            if mac:
                out[ip] = mac
    return out


def _parse_lan_devices(nmap_text: str, neigh_text: str) -> list[dict[str, Any]]:
    neigh_all = _parse_ip_neigh(neigh_text)
    neigh: dict[str, str] = {}
    for ip, mac in neigh_all.items():
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            continue
        neigh[ip] = mac

    ips: set[str] = set(neigh)
    for line in nmap_text.splitlines():
        m = re.match(r"Nmap scan report for\s+(?:.*\()?((?:\d{1,3}\.){3}\d{1,3})\)?$", line.strip())
        if m:
            candidate = m.group(1)
            try:
                ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                continue
            ips.add(candidate)
    return [
        {"ip": ip, "mac": neigh.get(ip), "hostname": None}
        for ip in sorted(ips, key=ipaddress.IPv4Address)
    ]


def _parse_integrity_text(text: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]{64})\s+(.+)$", line.strip())
        if m:
            out[m.group(2)] = {"sha256": m.group(1).lower()}
    return out


def _parse_sudo_group(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted(str(x) for x in value if x)
    if not isinstance(value, str) or not value.strip():
        return []
    text = value.strip()
    if ":" in text:
        members = text.split(":")[-1]
        return sorted(x.strip() for x in members.split(",") if x.strip())
    return sorted(x.strip() for x in text.split(",") if x.strip())


def _ping_reachable(text: str) -> bool | None:
    if not text.strip():
        return None
    if re.search(r"\b[1-9]\d*\s+received\b", text):
        return True
    m = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", text)
    if m:
        return float(m.group(1)) < 100.0
    if "bytes from" in text.lower():
        return True
    if "100% packet loss" in text.lower() or "network is unreachable" in text.lower():
        return False
    return None


def _memory_percentages(report: dict[str, Any]) -> tuple[float, float]:
    direct_ram = _first(report, [("resources", "ram_used_percent"), ("system", "ram_used_percent")])
    direct_swap = _first(report, [("resources", "swap_used_percent"), ("system", "swap_used_percent")])
    mem = _dig(report, "resources", "memory_bytes", default={})
    if not isinstance(mem, dict):
        mem = {}
    if direct_ram is None:
        total = _as_float(mem.get("total"))
        available = _as_float(mem.get("available"))
        ram = ((total - available) / total * 100.0) if total > 0 else 0.0
    else:
        ram = _as_float(direct_ram)
    if direct_swap is None:
        total = _as_float(mem.get("swap_total"))
        free = _as_float(mem.get("swap_free"))
        swap = ((total - free) / total * 100.0) if total > 0 else 0.0
    else:
        swap = _as_float(direct_swap)
    return max(0.0, ram), max(0.0, swap)


def _root_disk(report: dict[str, Any]) -> float:
    direct = _first(report, [
        ("storage", "root_used_percent"),
        ("storage", "root", "used_percent"),
        ("disk", "root_used_percent"),
    ])
    if direct is not None:
        return _as_float(direct)
    filesystems = _first(report, [("storage", "filesystems"), ("filesystems",)], default=[])
    if isinstance(filesystems, list):
        for fs in filesystems:
            if isinstance(fs, dict) and (fs.get("mountpoint") == "/" or fs.get("mount") == "/"):
                return _as_float(fs.get("used_percent") or fs.get("use_percent") or fs.get("capacity_percent"))
    return 0.0


def _uid0_users(report: dict[str, Any]) -> list[str]:
    value = _first(report, [
        ("security", "uid0_users"),
        ("security", "uid0_accounts"),
        ("users", "uid0"),
    ], default=[])
    if isinstance(value, int):
        return ["root"] if value == 1 else [f"uid0-{i}" for i in range(value)]
    if isinstance(value, str):
        value = [x for x in value.splitlines() if x.strip()]
    if not isinstance(value, list):
        return []
    out = []
    for item in value:
        if isinstance(item, dict):
            out.append(str(item.get("name") or item.get("user") or item.get("username") or item))
        else:
            text = str(item)
            out.append(text.split(":", 1)[0] if ":" in text else text)
    return sorted(set(x for x in out if x))


def _primary_interface(report: dict[str, Any]) -> tuple[str | None, str | None]:
    primary = _first(report, [("network", "primary_interface"), ("network", "default_route", "dev")])
    state = _first(report, [("network", "primary_state"), ("network", "interface_state")])
    interfaces = _dig(report, "network", "interfaces", default=[])
    if isinstance(interfaces, list):
        if primary:
            for item in interfaces:
                if isinstance(item, dict) and (item.get("ifname") == primary or item.get("name") == primary):
                    state = state or item.get("operstate") or item.get("state")
                    break
        if not primary:
            for item in interfaces:
                if not isinstance(item, dict):
                    continue
                name = item.get("ifname") or item.get("name")
                if name and name != "lo":
                    primary = str(name)
                    state = state or item.get("operstate") or item.get("state")
                    break
    return (str(primary) if primary else None, str(state) if state else None)


def _ssh_failed_count(text: str) -> int:
    return sum(1 for line in text.splitlines() if "Failed password" in line or "authentication failure" in line)


def normalize_report(report: dict[str, Any], report_path: Path | None = None) -> dict[str, Any]:
    ram_pct, swap_pct = _memory_percentages(report)
    primary_if, primary_state = _primary_interface(report)

    gateway = _first(report, [
        ("network", "default_gateway"),
        ("network", "gateway"),
        ("network", "default_route", "gateway"),
    ])
    dns = _first(report, [("network", "dns_servers"), ("network", "dns"), ("dns_servers",)], default=[])
    if isinstance(dns, str):
        dns = [x.strip() for x in re.split(r"[,\s]+", dns) if x.strip()]
    if not isinstance(dns, list):
        dns = []

    devices = _normalize_devices(_first(report, [
        ("lan", "devices"),
        ("network", "lan_devices"),
        ("lan_discovery", "devices"),
    ], default=[]))
    if not devices and report_path is not None:
        nmap_text = _read_raw(report_path, _first(report, [("network", "lan_discovery_file")], default="raw/lan_discovery.txt"))
        neigh_text = _read_raw(report_path, "raw/ip_neigh.txt")
        devices = _parse_lan_devices(nmap_text, neigh_text)

    listeners = _normalize_listeners(_first(report, [
        ("listening",),
        ("network", "listening_sockets"),
        ("services", "listening"),
    ], default=[]))

    integrity = _normalize_integrity(_first(report, [
        ("integrity",),
        ("security", "integrity"),
    ], default={}))
    if not integrity and report_path is not None:
        integrity_text = _read_raw(report_path, _first(report, [("security", "integrity_inventory_file")], default="raw/integrity_inventory.txt"))
        integrity = _parse_integrity_text(integrity_text)

    sudo_users = _first(report, [
        ("security", "sudo_users"),
        ("users", "sudo_users"),
    ], default=None)
    if sudo_users is None:
        sudo_users = _parse_sudo_group(_dig(report, "security", "sudo_group", default=""))
    elif not isinstance(sudo_users, list):
        sudo_users = _parse_sudo_group(sudo_users)

    ssh_failed_10m = _as_int(_first(report, [
        ("security", "ssh_failed_logins_10m"),
        ("security", "failed_ssh_10m"),
    ], default=0))
    security_events_text = ""
    if report_path is not None:
        security_events_text = _read_raw(report_path, _first(report, [("security", "security_events_file")], default="raw/security_events.txt"))
    ssh_failed_24h = _as_int(_first(report, [("security", "ssh_failed_logins_24h")], default=0)) or _ssh_failed_count(security_events_text)

    internet = _first(report, [
        ("network", "internet_reachable"),
        ("internet", "reachable"),
        ("internet", "online"),
    ], default=None)
    internet_bool = _as_bool(internet, None)
    if internet_bool is None and report_path is not None:
        ping_text = _read_raw(report_path, "raw/internet_ping.txt")
        internet_bool = _ping_reachable(ping_text)
        if internet_bool is None and _dig(report, "network", "internet_ping_collected", default=False):
            internet_bool = True

    firewall_active = _first(report, [
        ("security", "firewall_active"),
        ("firewall", "active"),
    ], default=None)

    normalized = {
        "meta": {
            "normalized_at": now_iso(),
            "source_generated_at": _first(report, [("meta", "generated_at"), ("generated_at",), ("timestamp",)]),
            "source_report": str(report_path) if report_path else None,
        },
        "system": {
            "hostname": _first(report, [("system", "hostname"), ("hostname",)]),
            "boot_id": _first(report, [("system", "boot_id"), ("boot_id",), ("system", "boot_time")]),
        },
        "resources": {
            "ram_used_percent": round(ram_pct, 2),
            "swap_used_percent": round(swap_pct, 2),
        },
        "storage": {"root_used_percent": _root_disk(report)},
        "network": {
            "default_gateway": gateway,
            "dns_servers": sorted(str(x) for x in dns),
            "public_ip": _first(report, [("network", "public_ip"), ("internet", "public_ip"), ("public_ip",)]),
            "primary_interface": primary_if,
            "primary_state": primary_state,
            "internet_reachable": internet_bool,
        },
        "lan": {"devices": devices},
        "listening": listeners,
        "security": {
            "uid0_users": _uid0_users(report),
            "sudo_users": sorted(str(x) for x in (sudo_users or []) if x),
            "ssh_failed_logins_10m": ssh_failed_10m,
            "ssh_failed_logins_24h": ssh_failed_24h,
            "firewall_active": _as_bool(firewall_active, None),
        },
        "services": {
            "openclaw_running": _as_bool(_first(report, [
                ("services", "openclaw_running"),
                ("openclaw", "process_detected"),
                ("openclaw", "running"),
            ]), None),
            "llm_runtime_running": _as_bool(_first(report, [
                ("services", "llm_runtime_running"),
                ("llm", "runtime_process_detected"),
                ("local_llm", "runtime_process_detected"),
                ("llm", "running"),
            ]), None),
        },
        "integrity": integrity,
    }
    return normalized


def validate_normalized(snapshot: dict[str, Any], *, for_baseline: bool) -> None:
    missing = []
    if not snapshot.get("system", {}).get("hostname"):
        missing.append("system.hostname")
    if snapshot.get("storage", {}).get("root_used_percent", 0) <= 0:
        missing.append("storage.root_used_percent")
    if for_baseline:
        if not snapshot.get("network", {}).get("default_gateway"):
            missing.append("network.default_gateway")
        if not snapshot.get("lan", {}).get("devices"):
            missing.append("lan.devices")
        if not snapshot.get("listening"):
            missing.append("listening")
        if snapshot.get("services", {}).get("openclaw_running") is None:
            missing.append("services.openclaw_running")
        if snapshot.get("services", {}).get("llm_runtime_running") is None:
            missing.append("services.llm_runtime_running")
    if missing:
        raise ValueError(
            "Phase 1 report could not be normalized safely for baseline. "
            "Missing/unrecognized fields: " + ", ".join(missing) +
            ". Do not create a baseline from this report; adjust field aliases first."
        )


def _device_key(device: dict[str, Any]) -> str:
    if device.get("mac"):
        return "mac:" + str(device["mac"]).lower()
    if device.get("hostname"):
        return "host:" + str(device["hostname"]).lower()
    return "ip:" + str(device.get("ip"))


def _listener_key(item: dict[str, Any]) -> str:
    return f"{item.get('proto')}:{item.get('address')}:{item.get('port')}"


def _change(change_type: str, entity: str, previous: Any = None, current: Any = None, basis: str = "previous") -> dict[str, Any]:
    return {
        "type": change_type,
        "entity": entity,
        "basis": basis,
        "previous": previous,
        "current": current,
    }


def semantic_diff(previous: dict[str, Any], current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    changes: list[dict[str, Any]] = []

    def add_if_changed(path: tuple[str, ...], change_type: str, entity: str) -> None:
        prev = _dig(previous, *path)
        cur = _dig(current, *path)
        if prev != cur:
            changes.append(_change(change_type, entity, prev, cur, "previous"))

    add_if_changed(("network", "default_gateway"), "GATEWAY_CHANGED", "default_gateway")
    add_if_changed(("network", "dns_servers"), "DNS_CHANGED", "dns")
    add_if_changed(("network", "public_ip"), "PUBLIC_IP_CHANGED", "public_ip")
    add_if_changed(("network", "primary_state"), "INTERFACE_STATE_CHANGED", str(current["network"].get("primary_interface")))
    add_if_changed(("system", "boot_id"), "REBOOT_DETECTED", "host")

    # LAN: compare against baseline for persistent deviations; previous is used for DHCP/IP movement.
    base_devices = {_device_key(x): x for x in baseline["lan"]["devices"]}
    cur_devices = {_device_key(x): x for x in current["lan"]["devices"]}
    prev_devices = {_device_key(x): x for x in previous["lan"]["devices"]}
    for key, dev in cur_devices.items():
        if key not in base_devices:
            changes.append(_change("LAN_DEVICE_NEW", key, None, dev, "baseline"))
        elif key in prev_devices and prev_devices[key].get("ip") != dev.get("ip"):
            changes.append(_change("LAN_DEVICE_IP_CHANGED", key, prev_devices[key].get("ip"), dev.get("ip"), "previous"))
    for key, dev in base_devices.items():
        if key not in cur_devices:
            changes.append(_change("LAN_DEVICE_MISSING", key, dev, None, "baseline"))

    base_listeners = {_listener_key(x): x for x in baseline["listening"]}
    cur_listeners = {_listener_key(x): x for x in current["listening"]}
    for key, item in cur_listeners.items():
        if key not in base_listeners:
            changes.append(_change("LISTENING_PORT_NEW", key, None, item, "baseline"))
    for key, item in base_listeners.items():
        if key not in cur_listeners:
            changes.append(_change("LISTENING_PORT_REMOVED", key, item, None, "baseline"))

    base_uid0 = set(baseline["security"].get("uid0_users", []))
    cur_uid0 = set(current["security"].get("uid0_users", []))
    for user in sorted(cur_uid0 - base_uid0):
        changes.append(_change("UID0_ADDED", user, None, user, "baseline"))

    base_sudo = set(baseline["security"].get("sudo_users", []))
    cur_sudo = set(current["security"].get("sudo_users", []))
    for user in sorted(cur_sudo - base_sudo):
        changes.append(_change("SUDO_USER_ADDED", user, None, user, "baseline"))

    base_integrity = baseline.get("integrity", {})
    cur_integrity = current.get("integrity", {})
    for path in sorted(set(base_integrity) | set(cur_integrity)):
        before = (base_integrity.get(path) or {}).get("sha256")
        after = (cur_integrity.get(path) or {}).get("sha256")
        if before != after:
            changes.append(_change("INTEGRITY_CHANGED", path, before, after, "baseline"))

    return {
        "generated_at": now_iso(),
        "changes": sorted(changes, key=lambda x: (x["type"], x["entity"])),
    }


def _is_public_listener(listener: dict[str, Any]) -> bool:
    address = str(listener.get("address") or "")
    return address in {"0.0.0.0", "::", "*"} or (
        address not in {"127.0.0.1", "::1", "localhost", ""} and not address.startswith("127.")
    )


def _finding(rule_id: str, severity: str, entity: str, evidence: str) -> dict[str, Any]:
    return {"rule_id": rule_id, "severity": severity, "entity": entity, "evidence": evidence}


def evaluate_rules(current: dict[str, Any], diff: dict[str, Any]) -> dict[str, Any]:
    findings: dict[tuple[str, str], dict[str, Any]] = {}

    def add(rule: str, sev: str, entity: str, evidence: str) -> None:
        findings[(rule, entity)] = _finding(rule, sev, entity, evidence)

    disk = float(current["storage"].get("root_used_percent", 0) or 0)
    if disk >= 95:
        add("DISK_ROOT_CRITICAL", "CRITICAL", "/", f"root filesystem used={disk:.1f}%")
    elif disk >= 90:
        add("DISK_ROOT_HIGH", "HIGH", "/", f"root filesystem used={disk:.1f}%")
    elif disk >= 80:
        add("DISK_ROOT_WARNING", "WARNING", "/", f"root filesystem used={disk:.1f}%")

    ram = float(current["resources"].get("ram_used_percent", 0) or 0)
    if ram >= 95:
        add("SYS_RAM_HIGH", "HIGH", "ram", f"ram used={ram:.1f}%")
    elif ram >= 85:
        add("SYS_RAM_WARNING", "WARNING", "ram", f"ram used={ram:.1f}%")

    swap = float(current["resources"].get("swap_used_percent", 0) or 0)
    if swap >= 90:
        add("SYS_SWAP_HIGH", "HIGH", "swap", f"swap used={swap:.1f}%")
    elif swap >= 50:
        add("SYS_SWAP_WARNING", "WARNING", "swap", f"swap used={swap:.1f}%")

    if current["network"].get("primary_state") and str(current["network"]["primary_state"]).upper() != "UP":
        add("NET_INTERFACE_DOWN", "CRITICAL", str(current["network"].get("primary_interface")), f"state={current['network']['primary_state']}")
    if current["network"].get("internet_reachable") is False:
        add("NET_INTERNET_DOWN", "HIGH", "internet", "internet reachability check failed")

    failed_10m = int(current["security"].get("ssh_failed_logins_10m", 0) or 0)
    failed_24h = int(current["security"].get("ssh_failed_logins_24h", 0) or 0)
    failed = failed_10m if failed_10m > 0 else failed_24h
    failed_window = "10m" if failed_10m > 0 else "24h"
    if failed >= 20:
        add("SEC_SSH_FAILURES", "CRITICAL", "ssh", f"failed logins in {failed_window}={failed}")
    elif failed >= 10:
        add("SEC_SSH_FAILURES", "HIGH", "ssh", f"failed logins in {failed_window}={failed}")
    elif failed >= 5:
        add("SEC_SSH_FAILURES", "WARNING", "ssh", f"failed logins in {failed_window}={failed}")

    if current["services"].get("openclaw_running") is False:
        add("SVC_OPENCLAW_DOWN", "HIGH", "openclaw", "OpenClaw process/service not detected")
    if current["services"].get("llm_runtime_running") is False:
        add("SVC_LLM_DOWN", "WARNING", "llm", "local LLM runtime not detected")
    if current["security"].get("firewall_active") is False:
        add("SEC_FIREWALL_DISABLED", "HIGH", "firewall", "firewall explicitly reported inactive")

    for change in diff.get("changes", []):
        t = change.get("type")
        entity = str(change.get("entity"))
        if t == "GATEWAY_CHANGED":
            add("NET_GATEWAY_CHANGED", "HIGH", entity, f"{change.get('previous')} -> {change.get('current')}")
        elif t == "DNS_CHANGED":
            add("NET_DNS_CHANGED", "WARNING", entity, f"{change.get('previous')} -> {change.get('current')}")
        elif t == "PUBLIC_IP_CHANGED":
            add("NET_PUBLIC_IP_CHANGED", "INFO", entity, f"{change.get('previous')} -> {change.get('current')}")
        elif t == "LAN_DEVICE_NEW":
            add("LAN_NEW_DEVICE", "WARNING", entity, json.dumps(change.get("current"), sort_keys=True))
        elif t == "LAN_DEVICE_MISSING":
            add("LAN_DEVICE_MISSING", "INFO", entity, json.dumps(change.get("previous"), sort_keys=True))
        elif t == "LAN_DEVICE_IP_CHANGED":
            add("LAN_DEVICE_IP_CHANGED", "INFO", entity, f"{change.get('previous')} -> {change.get('current')}")
        elif t == "LISTENING_PORT_NEW":
            listener = change.get("current") or {}
            sev = "HIGH" if _is_public_listener(listener) else "WARNING"
            add("NET_NEW_LISTENING_PORT", sev, entity, json.dumps(listener, sort_keys=True))
        elif t == "LISTENING_PORT_REMOVED":
            add("NET_LISTENING_PORT_REMOVED", "INFO", entity, json.dumps(change.get("previous"), sort_keys=True))
        elif t == "UID0_ADDED":
            add("SEC_NEW_UID0", "CRITICAL", entity, f"new UID 0 identity: {entity}")
        elif t == "SUDO_USER_ADDED":
            add("SEC_NEW_SUDO_USER", "HIGH", entity, f"new sudo/admin user: {entity}")
        elif t == "INTEGRITY_CHANGED":
            add("SEC_INTEGRITY_CHANGED", "HIGH", entity, f"hash changed for {entity}")
        elif t == "REBOOT_DETECTED":
            add("SYS_REBOOT_DETECTED", "INFO", entity, "boot_id changed")
        elif t == "INTERFACE_STATE_CHANGED":
            add("NET_INTERFACE_STATE_CHANGED", "HIGH", entity, f"{change.get('previous')} -> {change.get('current')}")

    result_findings = list(findings.values())
    severity = "OK"
    for item in result_findings:
        if SEVERITY[item["severity"]] > SEVERITY[severity]:
            severity = item["severity"]
    return {
        "generated_at": now_iso(),
        "severity": severity,
        "needs_ai_review": SEVERITY[severity] >= SEVERITY["WARNING"],
        "findings": sorted(result_findings, key=lambda x: (-SEVERITY[x["severity"]], x["rule_id"], x["entity"])),
    }


def latest_phase1_report(root: Path = DEFAULT_PHASE1_ROOT) -> Path:
    candidates = list(root.glob("*/discovery.json"))
    if not candidates:
        raise FileNotFoundError(f"No Phase 1 discovery.json found under {root}")
    return max(candidates, key=lambda p: p.stat().st_mtime)


def save_baseline(report_path: Path, monitor_root: Path = DEFAULT_ROOT) -> dict[str, Any]:
    raw = load_json(report_path)
    baseline = normalize_report(raw, report_path)
    validate_normalized(baseline, for_baseline=True)
    baseline["baseline_created_at"] = now_iso()
    baseline["source_report"] = str(report_path)
    atomic_json(monitor_root / "state" / "baseline.json", baseline)
    return baseline


def run_compare(report_path: Path, monitor_root: Path = DEFAULT_ROOT) -> dict[str, Any]:
    baseline_path = monitor_root / "state" / "baseline.json"
    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline missing: {baseline_path}. Run: compare.py baseline")

    baseline = load_json(baseline_path)
    current = normalize_report(load_json(report_path), report_path)
    validate_normalized(current, for_baseline=False)
    current["source_report"] = str(report_path)

    current_path = monitor_root / "state" / "current.json"
    previous_path = monitor_root / "state" / "previous.json"
    previous = load_json(current_path) if current_path.exists() else baseline

    diff = semantic_diff(previous, current, baseline)
    findings = evaluate_rules(current, diff)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_dir = monitor_root / "reports" / stamp
    archive_dir.mkdir(parents=True, exist_ok=True)
    atomic_json(archive_dir / "current.json", current)
    atomic_json(archive_dir / "diff.json", diff)
    atomic_json(archive_dir / "findings.json", findings)

    atomic_json(previous_path, previous)
    atomic_json(current_path, current)
    atomic_json(monitor_root / "diff.json", diff)
    atomic_json(monitor_root / "findings.json", findings)

    result = dict(findings)
    result["report"] = str(report_path)
    result["diff_count"] = len(diff.get("changes", []))
    return result


def print_summary(result: dict[str, Any]) -> None:
    print(f"Severity: {result.get('severity', 'UNKNOWN')}")
    print(f"AI review needed: {str(result.get('needs_ai_review', False)).lower()}")
    if "diff_count" in result:
        print(f"Changes: {result['diff_count']}")
    findings = result.get("findings", [])
    print(f"Findings: {len(findings)}")
    for item in findings:
        print(f"[{item['severity']}] {item['rule_id']} {item['entity']}: {item['evidence']}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="OpenClaw monitor Phase 2: baseline + diff + deterministic rules")
    p.add_argument("command", choices=["baseline", "run", "show"])
    p.add_argument("--report", type=Path, help="Phase 1 discovery.json. Default: newest under ~/openclaw-sentinel-phase1/")
    p.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="Monitor state directory")
    return p


def main() -> int:
    args = build_parser().parse_args()
    report_path = args.report.expanduser() if args.report else None
    root = args.root.expanduser()

    if args.command == "baseline":
        source = report_path or latest_phase1_report()
        baseline = save_baseline(source, root)
        print(f"Baseline saved: {root / 'state' / 'baseline.json'}")
        print(f"Source: {source}")
        print(f"Devices: {len(baseline['lan']['devices'])}")
        print(f"Listeners: {len(baseline['listening'])}")
        print(f"Root disk: {baseline['storage']['root_used_percent']:.1f}%")
        return 0

    if args.command == "run":
        source = report_path or latest_phase1_report()
        result = run_compare(source, root)
        print_summary(result)
        return 2 if SEVERITY[result["severity"]] >= SEVERITY["WARNING"] else 0

    findings_path = root / "findings.json"
    if not findings_path.exists():
        print("No findings.json yet.")
        return 1
    print_summary(load_json(findings_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
