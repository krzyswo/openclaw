#!/usr/bin/env bash
set -uo pipefail

VERSION="1.1.0"
OUTPUT_ROOT="${HOME}/openclaw-sentinel-phase1"
OFFLINE=0
COMMAND_TIMEOUT="${SENTINEL_COMMAND_TIMEOUT:-20}"
KILL_AFTER="${SENTINEL_KILL_AFTER:-2}"
VERSION_TIMEOUT="${SENTINEL_VERSION_TIMEOUT:-2}"
SKIP_EXTERNAL="${SENTINEL_SKIP_EXTERNAL:-0}"

usage() {
  cat <<USAGE
OpenClaw Sentinel - Phase 1 Discovery v${VERSION}

Usage:
  $0 [--output DIR] [--offline] [--help]

Options:
  --output DIR   Parent directory for the discovery run.
                 Default: ${OUTPUT_ROOT}
  --offline      Skip external Internet checks and public-IP lookup.
  --help         Show this help.

Safety:
  This collector is inventory/read-only. It does not change service state,
  package state, accounts, firewall rules, or system configuration.
  It only creates its own report directory and files.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || { echo "--output requires a directory" >&2; exit 2; }
      OUTPUT_ROOT="$2"; shift 2 ;;
    --offline)
      OFFLINE=1; shift ;;
    --help|-h)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2 ;;
  esac
done

umask 077
export PATH="/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"
START_EPOCH="$(date +%s)"
STAMP="$(date '+%Y%m%d_%H%M%S')"
RUN_DIR="${OUTPUT_ROOT%/}/${STAMP}"
RAW_DIR="${RUN_DIR}/raw"
mkdir -p "$RAW_DIR"
ERRORS="${RUN_DIR}/errors.log"
: > "$ERRORS"

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
record_error() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" >> "$ERRORS"; }
resolve_tool() {
  local tool="$1" found=""
  found="$(command -v "$tool" 2>/dev/null || true)"
  if [[ -n "$found" ]]; then
    printf '%s\n' "$found"
    return 0
  fi
  for dir in /usr/local/sbin /usr/sbin /sbin /usr/local/bin /usr/bin /bin; do
    if [[ -x "$dir/$tool" ]]; then
      printf '%s\n' "$dir/$tool"
      return 0
    fi
  done
  return 1
}
have() { resolve_tool "$1" >/dev/null 2>&1; }
tool_path() { resolve_tool "$1" 2>/dev/null || true; }

capture() {
  local name="$1"; shift
  local out="${RAW_DIR}/${name}.txt"
  if timeout --kill-after="${KILL_AFTER}s" "$COMMAND_TIMEOUT" "$@" </dev/null >"$out" 2>&1; then
    return 0
  else
    local rc=$?
    record_error "${name}: exit=${rc}: $*"
    return 0
  fi
}

capture_shell() {
  local name="$1"; shift
  local cmd="$*"
  local out="${RAW_DIR}/${name}.txt"
  if timeout --kill-after="${KILL_AFTER}s" "$COMMAND_TIMEOUT" bash -c "$cmd" </dev/null >"$out" 2>&1; then
    return 0
  else
    local rc=$?
    record_error "${name}: exit=${rc}: ${cmd}"
    return 0
  fi
}

capture_privileged_shell() {
  local name="$1"; shift
  local cmd="$*"
  local out="${RAW_DIR}/${name}.txt"
  if [[ "$(id -u)" -eq 0 ]]; then
    capture_shell "$name" "$cmd"
  elif have sudo && sudo -n true >/dev/null 2>&1; then
    if timeout --kill-after="${KILL_AFTER}s" "$COMMAND_TIMEOUT" sudo -n bash -c "$cmd" </dev/null >"$out" 2>&1; then
      return 0
    else
      local rc=$?
      record_error "${name}: privileged exit=${rc}: ${cmd}"
      return 0
    fi
  else
    printf 'UNAVAILABLE: requires root or non-interactive sudo\n' >"$out"
    record_error "${name}: privileged read unavailable"
  fi
}

capture_if_have() {
  local tool="$1" name="$2"; shift 2
  if have "$tool"; then
    capture "$name" "$@"
  else
    printf 'UNAVAILABLE: %s not found\n' "$tool" >"${RAW_DIR}/${name}.txt"
  fi
}

log "OpenClaw Sentinel Phase 1 discovery ${VERSION}"
log "Output: ${RUN_DIR}"
log "Collecting system inventory..."

# System identity and time
capture uname uname -a
capture hostname hostname
capture_shell os_release 'cat /etc/os-release 2>/dev/null || true'
capture_if_have hostnamectl hostnamectl hostnamectl
capture_if_have timedatectl timedatectl timedatectl
capture uptime uptime
capture_shell boot_time 'who -b 2>/dev/null || true'
capture_shell virtualization 'systemd-detect-virt 2>/dev/null || true'

# Hardware and resources
capture_if_have lscpu lscpu lscpu
# DMI/sysfs identity is available on most physical Linux hosts without extra packages.
capture_shell hardware_identity 'for f in /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/product_version /sys/class/dmi/id/board_vendor /sys/class/dmi/id/board_name /sys/class/dmi/id/board_version /sys/class/dmi/id/bios_vendor /sys/class/dmi/id/bios_version /sys/class/dmi/id/bios_date /sys/class/dmi/id/product_uuid; do if [ -r "$f" ]; then printf "%s=" "$f"; cat "$f"; fi; done'
if have dmidecode; then capture_privileged_shell dmi_summary 'dmidecode -t system -t baseboard -t bios -t memory 2>/dev/null | head -n 1200'; else printf 'UNAVAILABLE: dmidecode not found\n' >"${RAW_DIR}/dmi_summary.txt"; fi
capture_if_have free memory free -b
capture_shell meminfo 'cat /proc/meminfo 2>/dev/null || true'
capture_if_have swapon swap swapon --show --bytes
capture_if_have lspci pci lspci -nnk
capture_if_have lsusb usb lsusb
capture_shell cpu_load 'cat /proc/loadavg 2>/dev/null || true'
capture_shell cpu_stat 'cat /proc/stat 2>/dev/null | head -n 10 || true'

if have sensors; then capture sensors sensors; else printf 'UNAVAILABLE: sensors not found\n' >"${RAW_DIR}/sensors.txt"; fi
capture_shell thermal_zones 'for z in /sys/class/thermal/thermal_zone*; do [ -d "$z" ] || continue; echo "===== $z ====="; [ -r "$z/type" ] && cat "$z/type"; [ -r "$z/temp" ] && cat "$z/temp"; done'

# Storage
capture_if_have lsblk lsblk lsblk -J -O
capture_if_have blkid blkid blkid
capture_shell mdraid 'cat /proc/mdstat 2>/dev/null || true'
for t in pvs vgs lvs; do if have "$t"; then capture "$t" "$t" --reportformat json; else printf 'UNAVAILABLE: %s not found\n' "$t" >"${RAW_DIR}/${t}.txt"; fi; done
if have nvme; then capture nvme_list nvme list -o json; else printf 'UNAVAILABLE: nvme not found\n' >"${RAW_DIR}/nvme_list.txt"; fi
capture_if_have findmnt findmnt findmnt -J
capture_shell mount_options 'findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || mount'
capture df_bytes df -P -B1
capture df_inodes df -Pi
capture_shell largest_dirs 'for d in /var /home /opt; do [ -d "$d" ] && timeout 25 du -x -B1 -d 1 "$d" 2>/dev/null; done | sort -nr | head -n 80'
if have smartctl; then
  capture smart_scan smartctl --scan-open
  capture_privileged_shell smart_summary 'for d in $(smartctl --scan-open 2>/dev/null | awk "{print \$1}"); do echo "===== $d ====="; smartctl -H -A "$d" 2>&1; done'
else
  printf 'UNAVAILABLE: smartctl not found\n' >"${RAW_DIR}/smart_scan.txt"
  printf 'UNAVAILABLE: smartctl not found\n' >"${RAW_DIR}/smart_summary.txt"
fi

# Network interfaces, routes, neighbours, DNS
if have ip; then
  capture ip_addr_json ip -j addr
  capture ip_route_json ip -j route
  capture ip_link_stats ip -s link
  capture network_counters ip -s -j link
  capture ip_rule_json ip -j rule
  capture ip_route6_json ip -6 -j route
  capture ip_neigh ip neigh show
else
  printf 'UNAVAILABLE: ip not found\n' >"${RAW_DIR}/ip_addr_json.txt"
  printf 'UNAVAILABLE: ip not found\n' >"${RAW_DIR}/ip_route_json.txt"
  printf 'UNAVAILABLE: ip not found\n' >"${RAW_DIR}/ip_link_stats.txt"
  printf 'UNAVAILABLE: ip not found\n' >"${RAW_DIR}/ip_neigh.txt"
fi
capture_shell resolv_conf 'cat /etc/resolv.conf 2>/dev/null || true'
if have resolvectl; then capture resolvectl_status resolvectl status; else printf 'UNAVAILABLE: resolvectl not found\n' >"${RAW_DIR}/resolvectl_status.txt"; fi
if have nmcli; then capture nmcli_devices nmcli -t -f GENERAL.DEVICE,GENERAL.TYPE,GENERAL.STATE,GENERAL.CONNECTION,IP4.ADDRESS,IP4.GATEWAY device show; else printf 'UNAVAILABLE: nmcli not found\n' >"${RAW_DIR}/nmcli_devices.txt"; fi
capture_shell nic_details 'for i in /sys/class/net/*; do n=$(basename "$i"); echo "===== $n ====="; [ -r "$i/address" ] && echo -n "mac=" && cat "$i/address"; [ -r "$i/operstate" ] && echo -n "state=" && cat "$i/operstate"; [ -r "$i/mtu" ] && echo -n "mtu=" && cat "$i/mtu"; if command -v ethtool >/dev/null 2>&1; then ethtool "$n" 2>/dev/null | grep -E "Speed:|Duplex:|Link detected:" || true; ethtool -i "$n" 2>/dev/null | grep -E "driver:|version:|firmware-version:|bus-info:" || true; fi; done'

if have ss; then
  capture ss_listening ss -H -tulpn
  capture ss_established ss -H -tunap state established
else
  printf 'UNAVAILABLE: ss not found\n' >"${RAW_DIR}/ss_listening.txt"
  printf 'UNAVAILABLE: ss not found\n' >"${RAW_DIR}/ss_established.txt"
fi

# Local connectivity and conservative LAN host discovery
GATEWAY=""
LAN_CIDR=""
if have ip; then
  LAN_CIDR="$(ip -o -4 addr show scope global 2>/dev/null | awk 'NR==1{print $4}')"
fi
printf '%s\n' "${LAN_CIDR:-UNAVAILABLE}" >"${RAW_DIR}/lan_cidr.txt"
if [[ -n "$LAN_CIDR3" ]] && have nmap; then
  capture lan_discovery nmap -sn -n --max-retries 1 --host-timeout 3s "$LAN_CIDR3"
elif have arp-scan; then
  capture_privileged_shell lan_discovery 'arp-scan --localnet 2>&1'
else
  printf 'UNAVAILABLE: nmap/arp-scan not found; using neighbour table only\n' >"${RAW_DIR}/lan_discovery.txt"
fi
if have ip; then GATEWAY="$(ip route show default 2>/dev/null | awk 'NR==1{print $3}')"; fi
if [[ -n "$GATEWAY" ]] && have ping; then capture gateway_ping ping -c 3 -W 2 "$GATEWAY"; else printf 'UNAVAILABLE: gateway or ping missing\n' >"${RAW_DIR}/gateway_ping.txt"; fi
if [[ "$OFFLINE" -eq 0 && "$SKIP_EXTERNAL" != "1" ]]; then
  capture_shell dns_resolution 'getent ahostsv4 example.com 2>/dev/null | head -n 10 || true'
else
  printf 'SKIPPED: offline mode\n' >"${RAW_DIR}/dns_resolution.txt"
fi

if [[ "$OFFLINE" -eq 0 && "$SKIP_EXTERNAL" != "1" ]]; then
  if have ping; then capture internet_ping ping -c 3 -W 2 1.1.1.1; else printf 'UNAVAILABLE: ping not found\n' >"${RAW_DIR}/internet_ping.txt"; fi
  if have curl; then
    capture curl_https curl -fsSI --max-time 6 https://example.com
    capture public_ip curl -fsS --max-time 6 https://api64.ipify.org
  else
    printf 'UNAVAILABLE: curl not found\n' >"${RAW_DIR}/curl_https.txt"
    printf 'UNAVAILABLE: curl not found\n' >"${RAW_DIR}/public_ip.txt"
  fi
else
  printf 'SKIPPED: offline mode\n' >"${RAW_DIR}/internet_ping.txt"
  printf 'SKIPPED: offline mode\n' >"${RAW_DIR}/curl_https.txt"
  printf 'SKIPPED: offline mode\n' >"${RAW_DIR}/public_ip.txt"
fi

# Firewall inventory
if have nft; then capture_privileged_shell nft_ruleset 'nft list ruleset'; else printf 'UNAVAILABLE: nft not found\n' >"${RAW_DIR}/nft_ruleset.txt"; fi
if have iptables; then capture_privileged_shell iptables_rules 'iptables -S'; else printf 'UNAVAILABLE: iptables not found\n' >"${RAW_DIR}/iptables_rules.txt"; fi
if have ufw; then capture_privileged_shell ufw_status 'ufw status verbose'; else printf 'UNAVAILABLE: ufw not found\n' >"${RAW_DIR}/ufw_status.txt"; fi
if have firewall-cmd; then capture firewall_cmd_state firewall-cmd --state; else printf 'UNAVAILABLE: firewall-cmd not found\n' >"${RAW_DIR}/firewall_cmd_state.txt"; fi

# Users, groups and SSH posture
# File integrity inventory stores hashes/metadata only; no secret configuration contents.
capture_privileged_shell integrity_inventory 'files="/etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /etc/hosts /etc/resolv.conf /etc/nftables.conf"; for f in $files; do if [ -e "$f" ]; then stat -c "%a %U:%G %s %y %n" "$f"; sha256sum "$f" 2>/dev/null || true; else echo "MISSING $f"; fi; done; for d in /etc/sudoers.d /etc/ssh/sshd_config.d; do if [ -d "$d" ]; then find "$d" -maxdepth 1 -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum; fi; done'
capture_shell passwd_inventory 'getent passwd'
capture_shell group_inventory 'getent group'
capture_shell uid0_accounts 'getent passwd | awk -F: "\$3 == 0 {print \$1\":\" \$3\":\" \$7\"}"'
capture_shell sudo_group 'getent group sudo 2>/dev/null || true'
capture_shell admin_group 'getent group admin 2>/dev/null || true'
if have sshd; then capture_privileged_shell sshd_effective 'sshd -T'; else printf 'UNAVAILABLE: sshd not found\n' >"${RAW_DIR}/sshd_effective.txt"; fi
capture_shell ssh_config_hashes 'for f in /etc/ssh/sshd_config /etc/ssh/ssh_config /etc/passwd /etc/group /etc/hosts /etc/resolv.conf /etc/sudoers /etc/nftables.conf; do if [ -r "$f" ]; then sha256sum "$f"; else echo "UNREADABLE $f"; fi; done'
capture_shell current_authorized_keys 'if [ -r "$HOME/.ssh/authorized_keys" ]; then ssh-keygen -lf "$HOME/.ssh/authorized_keys" 2>/dev/null || sha256sum "$HOME/.ssh/authorized_keys"; else echo "NONE_OR_UNREADABLE"; fi
capture_privileged_shell authorized_keys_inventory 'while IFS=: read -r 