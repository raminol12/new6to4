#!/usr/bin/env bash

# Strict mode (portable)
set -eu
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

# ---- Colors (auto-disable if not supported) ----
use_color=0
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  if [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    use_color=1
  fi
fi

if [[ "$use_color" -eq 1 ]]; then
  C_RESET="$(tput sgr0)"
  C_BOLD="$(tput bold)"
  C_RED="$(tput setaf 1)"
  C_GREEN="$(tput setaf 2)"
  C_YELLOW="$(tput setaf 3)"
  C_BLUE="$(tput setaf 4)"
  C_MAGENTA="$(tput setaf 5)"
  C_CYAN="$(tput setaf 6)"
  C_WHITE="$(tput setaf 7)"
else
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""; C_WHITE=""
fi

# ---- Validation helpers ----
is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local o1 o2 o3 o4
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$o" =~ ^[0-9]+$ ]] || return 1
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

is_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 )) || return 1
  return 0
}

prompt_ipv4() {
  local prompt="$1"
  local ip=""
  while true; do
    read -rp "$prompt" ip
    if is_ipv4 "$ip"; then
      echo "$ip"
      return 0
    fi
    echo "${C_RED}ERROR:${C_RESET} Invalid IPv4. Example: 1.2.3.4"
  done
}

prompt_port() {
  local prompt="$1"
  local default="$2"
  local p=""
  while true; do
    read -rp "$prompt" p
    p="${p:-$default}"
    if is_port "$p"; then
      echo "$p"
      return 0
    fi
    echo "${C_RED}ERROR:${C_RESET} Invalid port. Range: 1-65535"
  done
}

get_local_ipv4() {
  local ip=""
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1 || true)"
  if [[ -z "$ip" ]]; then
    ip="$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  fi
  if [[ -z "$ip" ]]; then
    echo "${C_RED}ERROR:${C_RESET} Could not detect server IPv4 automatically."
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
  echo "${C_GREEN}OK:${C_RESET} Iran configuration written to ${C_CYAN}$RC_LOCAL${C_RESET}"
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
  echo "${C_GREEN}OK:${C_RESET} Foreign configuration written to ${C_CYAN}$RC_LOCAL${C_RESET}"
}

ping_quiet() {
  local target="$1"
  ping -c 1 -W 1 "$target" >/dev/null 2>&1
}

iface_exists() {
  ip link show dev "$1" >/dev/null 2>&1
}

iface_up() {
  ip link show dev "$1" 2>/dev/null | grep -q "state UP"
}

has_ipv4() {
  local dev="$1" cidr="$2"
  ip -4 addr show dev "$dev" 2>/dev/null | grep -q "$cidr"
}

has_ipv6() {
  local dev="$1" cidr="$2"
  ip -6 addr show dev "$dev" 2>/dev/null | grep -q "$cidr"
}

status_check() {
  # Detect which side based on existing interfaces; require interfaces+IPs+ping
  local side="" six="" gre="" want_v6="" want_v4=""

  if iface_exists "GRE6Tun_iran" || iface_exists "6to4_iran"; then
    side="IRAN"
    six="6to4_iran"
    gre="GRE6Tun_iran"
    want_v6="2002:a00:100::1/64"
    want_v4="10.10.187.1/30"
  elif iface_exists "GRE6Tun_Forign" || iface_exists "6to4_Forign"; then
    side="FOREIGN"
    six="6to4_Forign"
    gre="GRE6Tun_Forign"
    want_v6="2002:a00:100::2/64"
    want_v4="10.10.187.2/30"
  else
    echo "${C_RED}${C_BOLD}OFFLINE${C_RESET}"
    return 0
  fi

  # Interface existence
  iface_exists "$six" || { echo "${C_RED}${C_BOLD}OFFLINE${C_RESET}"; return 0; }
  iface_exists "$gre" || { echo "${C_RED}${C_BOLD}OFFLINE${C_RESET}"; return 0; }

  # Must be UP
  iface_up "$six" || { echo "${C_RED}${C_BOLD}OFFLINE${C_RESET}"; return 0; }
  iface_up "$gre" || { echo "${C_RED}${C_BOLD}OFFLINE${C_RESET}"; return 0; }

  # Must have expected IPs
  has_ipv6 "$six" "$want_v6" || { echo "${C_RED}${C_BOLD}OFFLINE${C_RESET}"; return 0; }
  has_ipv4 "$gre" "$want_v4" || { echo "${C_RED}${C_BOLD}OFFLINE${C_RESET}"; return 0; }

  # Must ping BOTH ends
  if ping_quiet 10.10.187.1 && ping_quiet 10.10.187.2; then
    echo "${C_GREEN}${C_BOLD}ONLINE${C_RESET}"
  else
    echo "${C_RED}${C_BOLD}OFFLINE${C_RESET}"
  fi
}

confirm_and_reboot() {
  local summary="$1"
  local ans=""

  echo
  echo "${C_CYAN}--------------------------------------${C_RESET}"
  echo "${C_BOLD}Summary${C_RESET}"
  echo "$summary"
  echo "${C_CYAN}--------------------------------------${C_RESET}"
  read -rp "Proceed to reboot? [Y/n]: " ans
  ans="${ans:-Y}"

  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    echo "${C_YELLOW}Reboot skipped.${C_RESET}"
    return 0
  fi

  echo "${C_YELLOW}Reboot will start in 5 seconds. Press Ctrl+C to cancel...${C_RESET}"
  local cancelled=0
  trap 'cancelled=1' INT

  for i in 5 4 3 2 1; do
    if [[ "$cancelled" -eq 1 ]]; then
      echo
      echo "${C_YELLOW}Reboot cancelled. Returning to menu...${C_RESET}"
      trap - INT
      return 0
    fi
    echo -ne "${C_YELLOW}Rebooting in ${i}...${C_RESET}\r"
    sleep 1
  done
  echo

  trap - INT
  reboot
}

print_banner() {
  echo "${C_CYAN}======================================${C_RESET}"
  echo "${C_BOLD}${C_MAGENTA}   Tunnel Menu (Iran <-> Foreign)${C_RESET}"
  echo "${C_CYAN}======================================${C_RESET}"
  echo "${C_YELLOW}${C_BOLD}   Developer:${C_RESET} ${C_WHITE}Telegram${C_RESET} ${C_GREEN}@mrraminol${C_RESET}"
  echo "${C_CYAN}--------------------------------------${C_RESET}"
}

menu() {
  while true; do
    clear || true
    print_banner
    echo "${C_WHITE}1)${C_RESET} Setup on Iran server"
    echo "${C_WHITE}2)${C_RESET} Setup on Foreign server"
    echo "${C_WHITE}3)${C_RESET} Ping 10.10.187.2"
    echo "${C_WHITE}4)${C_RESET} Ping 10.10.187.1"
    echo "${C_WHITE}5)${C_RESET} Status (ONLINE/OFFLINE)"
    echo "${C_WHITE}0)${C_RESET} Exit"
    echo "${C_CYAN}--------------------------------------${C_RESET}"
    read -rp "Select an option: " choice

    case "${choice}" in
      1)
        local iran_ip foreign_ip ssh_port
        iran_ip="$(get_local_ipv4)"
        echo "${C_GREEN}Detected Iran server IP (local):${C_RESET} ${C_CYAN}${iran_ip}${C_RESET}"

        foreign_ip="$(prompt_ipv4 "Enter Foreign server IPv4: ")"
        ssh_port="$(prompt_port "Iran SSH port (default 22): " "22")"

        write_rc_local_iran "$foreign_ip" "$iran_ip" "$ssh_port"

        confirm_and_reboot "Mode: IRAN
Local (Iran) IP:   $iran_ip
Remote (Foreign):  $foreign_ip
SSH Port:          $ssh_port
rc.local:          $RC_LOCAL"
        ;;
      2)
        local foreign_local iran_ip
        foreign_local="$(get_local_ipv4)"
        echo "${C_GREEN}Detected Foreign server IP (local):${C_RESET} ${C_CYAN}${foreign_local}${C_RESET}"

        iran_ip="$(prompt_ipv4 "Enter Iran server IPv4: ")"

        write_rc_local_foreign "$iran_ip" "$foreign_local"

        confirm_and_reboot "Mode: FOREIGN
Local (Foreign) IP: $foreign_local
Remote (Iran):      $iran_ip
rc.local:           $RC_LOCAL"
        ;;
      3)
        echo "${C_BLUE}Pinging 10.10.187.2 ...${C_RESET}"
        ping -c 4 -W 1 10.10.187.2 || true
        read -rp "Press Enter to continue..."
        ;;
      4)
        echo "${C_BLUE}Pinging 10.10.187.1 ...${C_RESET}"
        ping -c 4 -W 1 10.10.187.1 || true
        read -rp "Press Enter to continue..."
        ;;
      5)
        # prints ONLY ONLINE/OFFLINE (colored)
        status_check
        read -rp "Press Enter to continue..."
        ;;
      0)
        exit 0
        ;;
      *)
        echo "${C_RED}Invalid option!${C_RESET}"
        sleep 1
        ;;
    esac
  done
}

require_root
menu
