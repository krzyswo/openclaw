# OpenClaw Sentinel — Phase 1 Discovery v1.1.0

Read-only discovery collector for Debian/OpenClaw hosts.

It collects local evidence for:
- system and hardware identity
- CPU/RAM/swap and thermal capability
- disks, filesystems, mount options, LVM/mdraid/NVMe/SMART capability
- interfaces, NIC driver/link data, routes, DNS, counters, neighbours
- conservative LAN host discovery when `nmap` or `arp-scan` already exists
- Internet reachability/public IP unless `--offline` is used
- users, UID 0, sudo/admin groups, SSH posture, login/security events
- integrity hashes/metadata for selected critical configuration files
- firewall read-only inventory
- systemd services/timers, cron, processes, zombie processes
- packages, pending updates and apt history
- kernel/journal stability signals, reboot/shutdown history
- Docker capability
- OpenClaw process, runtime Node path/version, user units and config hashes
- local LLM runtime/endpoints and Ollama version when available
- Wi-Fi capability only; it does not scan surrounding SSIDs in Phase 1
- UPS/power capability
- NTP/time synchronization
- collector self-health and missing capability manifest

## Safety

The collector is read-only with respect to the host configuration:
- no package installation or upgrade
- no service start/stop/restart/enable/disable
- no firewall changes
- no user/group changes
- no remediation actions
- private SSH keys and OpenClaw configuration contents are not collected

The only writes are the collector's own report files.

## Run

```bash
chmod +x ~/openclaw-sentinel-discovery.sh
sudo -v
~/openclaw-sentinel-discovery.sh
```

Offline mode:

```bash
~/openclaw-sentinel-discovery.sh --offline
```

## Main outputs

- `discovery.json`
- `discovery.md`
- `errors.log`
- `capability_gaps.txt`
- `manifest.txt`
- `raw/`

## Phase boundary

Phase 1 only discovers and records the current environment. It does not declare the current state safe and does not create a security baseline.

Phase 2 will add:
- normalized snapshots
- approved baseline state
- deterministic diffing
- deterministic rules and severity

AI review and notifications remain separate later phases.

## Repository privacy note

Do not commit generated `raw/`, `discovery.json`, `discovery.md`, security logs, public IP addresses, LAN inventory, or SSH activity from a real environment into a public repository. Keep runtime evidence local or in an appropriately protected private store.
