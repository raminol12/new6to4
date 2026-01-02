#!/usr/bin/env bash

# Strict mode (portable)
set -eu
# Enable pipefail if supported (safe on bash; doesn't crash if not supported)
(set -o pipefail) 2>/dev/null && set -o pipefail

RC_LOCAL="/etc/rc.local"
RC_LOCAL_SERVICE="/etc/systemd/system/rc-local.service"

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "This script must be run as root. Example:"
    echo "sudo bash $0"
    exit 1
  fi
}

get_local_ipv4() {
  local ip=""
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1 || true)"
  if [[ -z "$ip" ]]; then
    ip="$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  fi
  if [[ -z "$ip" ]]; then
    echo "ERROR: Could not detect server IPv4 automatically."
    exit 1
  fi
  echo "$ip"
}

backup_rc_local() {
  if [[ -f "$RC_LOCAL" ]]; then
    cp -a "$RC_LOCAL" "${RC_LOCAL}.bak.$(date +%F_%H%M%S)"
  fi
}

ensure_rc_local_enabled() {
  if [[ ! -f "$RC_LOCAL" ]]; then
    cat > "$RC_LOCAL" <<'EORC'
#!/bin/bash
exit 0
EORC
    chmod +x "$RC_LOCAL"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    if [[ ! -f "$RC_LOCAL_SERVICE" ]]; then
      cat > "$RC_LOCAL_SERVICE" <<'EOSVC'
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
RemainAfterExit=yes
GuessMainPID=no

[Install]
WantedBy=multi-user.target
EOSVC
      systemctl daemon-reload
    fi
    systemctl enable rc-local.service >/dev/null 2>&1 || true
  fi
}

write_rc_local_iran() {
  local foreign_ip="$1"
  local iran_ip="$2"
  local ssh_port="$3"

  backup_rc_local
  ensure_rc_local_enabled

  cat > "$RC_LOCAL" <<EOFRC
#! /bin/bash

# Cleanup old tunnels (ignore errors)
ip tunnel del 6to4_iran 2>/dev/null || true
ip -6 tunnel del GRE6Tun_iran 2>/dev/null || true

ip tunnel add 6to4_iran mode sit remote ${foreign_ip} local ${iran_ip}

ip -6 addr add 2002:a00:100::1/64 dev 6to4_iran
ip link set 6to4_iran mtu 1480
ip link set 6to4_iran up

ip -6 tunnel add GRE6Tun_iran mode ip6gre remote 2002:a00:100::2 local 2002:a00:100::1
ip addr add 10.10.187.1/30 dev GRE6Tun_iran
ip link set GRE6Tun_iran mtu 1436
ip link set GRE6Tun_iran up

sysctl net.ipv4.ip_forward=1

iptables -t nat -A PREROUTING -p tcp --dport ${ssh_port} -j DNAT --to-destination 10.10.187.1
iptables -t nat -A PREROUTING -j DNAT --to-destination 10.10.187.2
iptables -t nat -A POSTROUTING -j MASQUERADE

exit 0
EOFRC

  chmod +x "$RC_LOCAL"
  echo "OK: Iran configuration written to $RC_LOCAL"
}

write_rc_local_foreign() {
  local iran_ip="$1"
  local foreign_ip="$2"

  backup_rc_local
  ensure_rc_local_enabled

  cat > "$RC_LOCAL" <<EOFRC
#! /bin/bash

# Cleanup old tunnels (ignore errors)
ip tunnel del 6to4_Forign 2>/dev/null || true
ip -6 tunnel del GRE6Tun_Forign 2>/dev/null || true

ip tunnel add 6to4_Forign mode sit remote ${iran_ip} local ${foreign_ip}

ip -6 addr add 2002:a00:100::2/64 dev 6to4_Forign
ip link set 6to4_Forign mtu 1480
ip link set 6to4_Forign up

ip -6 tunnel add GRE6Tun_Forign mode ip6gre remote 2002:a00:100::1 local 2002:a00:100::2
ip addr add 10.10.187.2/30 dev GRE6Tun_Forign
ip link set GRE6Tun_Forign mtu 1436
ip link set GRE6Tun_Forign up

exit 0
EOFRC

  chmod +x "$RC_LOCAL"
  echo "OK: Foreign configuration written to $RC_LOCAL"
}

reboot_now() {
  echo "Rebooting now..."
  sleep 2
  reboot
}

ping_quiet() {
  local target="$1"
  ping -c 1 -W 1 "$target" >/dev/null 2>&1
}

status_check() {
  # Print ONLY ONLINE / OFFLINE (requires BOTH pings to succeed)
  if ping_quiet 10.10.187.1 && ping_quiet 10.10.187.2; then
    echo "ONLINE"
  else
    echo "OFFLINE"
  fi
}

menu() {
  while true; do
    clear || true
    echo "======================================"
    echo "  Tunnel Menu (Iran <-> Foreign)"
    echo "======================================"
    echo "1) Setup on Iran server"
    echo "2) Setup on Foreign server"
    echo "3) Ping 10.10.187.2"
    echo "4) Ping 10.10.187.1"
    echo "5) Status (ONLINE/OFFLINE)"
    echo "0) Exit"
    echo "--------------------------------------"
    read -rp "Select an option: " choice

    case "${choice}" in
      1)
        local iran_ip foreign_ip ssh_port
        iran_ip="$(get_local_ipv4)"
        echo "Detected Iran server IP (local): ${iran_ip}"
        read -rp "Enter Foreign server IP: " foreign_ip
        read -rp "Iran SSH port (default 22): " ssh_port
        ssh_port="${ssh_port:-22}"

        if [[ -z "${foreign_ip}" ]]; then
          echo "ERROR: Foreign IP is empty."
          read -rp "Press Enter to continue..."
          continue
        fi

        write_rc_local_iran "$foreign_ip" "$iran_ip" "$ssh_port"
        reboot_now
        ;;
      2)
        local foreign_ip iran_ip
        foreign_ip="$(get_local_ipv4)"
        echo "Detected Foreign server IP (local): ${foreign_ip}"
        read -rp "Enter Iran server IP: " iran_ip

        if [[ -z "${iran_ip}" ]]; then
          echo "ERROR: Iran IP is empty."
          read -rp "Press Enter to continue..."
          continue
        fi

        write_rc_local_foreign "$iran_ip" "$foreign_ip"
        reboot_now
        ;;
      3)
        echo "Pinging 10.10.187.2 ..."
        ping -c 4 -W 1 10.10.187.2 || true
        read -rp "Press Enter to continue..."
        ;;
      4)
        echo "Pinging 10.10.187.1 ..."
        ping -c 4 -W 1 10.10.187.1 || true
        read -rp "Press Enter to continue..."
        ;;
      5)
        status_check
        read -rp "Press Enter to continue..."
        ;;
      0)
        exit 0
        ;;
      *)
        echo "Invalid option!"
        sleep 1
        ;;
    esac
  done
}

require_root
menu
