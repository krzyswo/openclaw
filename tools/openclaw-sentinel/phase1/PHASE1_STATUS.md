# OpenClaw Sentinel — Phase 1 Status

Status: COMPLETE

Date: 2026-09-09
Collector validated: v1.1.0

## Objective

Phase 1 establishes a read-only inventory of the OpenClaw host and confirms which telemetry sources are available before creating any baseline or alert rules.

## Validated coverage

The collector successfully covers:

- Debian/Linux identity and kernel
- virtualization detection
- CPU, RAM, swap and load
- filesystems and storage layout
- interface inventory, IPv4/IPv6, routing and DNS
- NIC counters and neighbour table
- LAN host discovery through nmap/arp-scan when available
- Internet reachability and optional public-IP probe
- listening sockets and established connections
- users, UID 0, sudo/admin inventory
- effective SSH configuration and login/security events
- integrity hashes for selected configuration files
- systemd services, failed units and timers
- cron jobs and processes
- package/update posture and apt history
- kernel/journal stability signals
- reboot/shutdown history
- OpenClaw process and runtime Node detection
- local LLM/Ollama runtime discovery
- time/NTP state
- Wi-Fi capability detection
- UPS/power capability detection
- collector self-health and capability-gap reporting

## Environment conclusions

The validated OpenClaw installation is running inside a KVM/QEMU virtual machine. Because of that, physical host sensors such as disk SMART data, physical NVMe health and motherboard/CPU thermal sensors are host-level telemetry rather than mandatory VM-level Phase 1 requirements.

The VM has no Wi-Fi sensor. Surrounding SSID/BSSID/channel/RSSI monitoring is therefore deferred to the dedicated Wi-Fi phase and will require suitable hardware.

UPS telemetry is deferred until a UPS or a host-side power data source is available.

A local host firewall is not assumed to be present. Later rules should evaluate actual service exposure/listening addresses and upstream network architecture instead of treating absence of nftables/iptables/ufw as an automatic critical fault.

LAN discovery is available once nmap/arp-scan is present.

## Items intentionally not committed

Runtime evidence may contain infrastructure-sensitive information. Do not commit:

- discovery.json
- discovery.md generated from a real host
- raw collector output
- errors containing environment details
- LAN IP/MAC/device inventory
- public IP addresses
- SSH/login history
- local service/process evidence

## Next phase

Phase 2 will remain deterministic and will implement:

1. normalized current snapshots
2. approved baseline creation
3. previous/current/baseline comparison
4. deterministic change events
5. deterministic INFO/WARNING/HIGH/CRITICAL rules
6. suppression/allow-list handling for expected devices, services and admin sources

AI analysis is explicitly outside Phase 2 and will consume deterministic findings in Phase 3.
