#!/usr/bin/env bash
set +e

RED="\e[31m"
GREEN="\e[32m"
PINK="\e[95m"
BLUE="\e[34m"
YELLOW="\e[33m"
CYAN="\e[36m"
PURPLE="\e[35m"
RESET="\e[0m"
BOLD="\e[1m"

FOOTER_TEXT="You Can RUN WS/TCP/QUIC/ICMP Tunneling Between One-to-Multi Server and Forward TCP/UDP Ports"

NOTICE_MAX=6
declare -a NOTICES=()

add_notice() {
  local msg="$1"
  NOTICES+=("$msg")
  if ((${#NOTICES[@]} > NOTICE_MAX)); then
    NOTICES=("${NOTICES[@]: -NOTICE_MAX}")
  fi
}

render_notices() {
  if ((${#NOTICES[@]} == 0)); then
    echo -e "${BOLD}${YELLOW}Info:${RESET} No actions yet."
  else
    echo -e "${BOLD}${YELLOW}Info / Logs:${RESET}"
    for n in "${NOTICES[@]}"; do
      echo -e " ${BOLD}- ${RESET}$n"
    done
  fi
}

clear_screen() { clear; }

render_banner() {
  echo -e "${BOLD}${CYAN}"
  cat <<'EOF'
██╗   ██╗ ██████╗ ██╗   ██╗███████╗ █████╗ ███████╗███████╗
╚██╗ ██╔╝██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝
 ╚████╔╝ ██║   ██║██║   ██║███████╗███████║█████╗  █████╗  
  ╚██╔╝  ██║   ██║██║   ██║╚════██║██╔══██║██╔══╝  ██╔══╝  
   ██║   ╚██████╔╝╚██████╔╝███████║██║  ██║██║     ███████╗
   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝
EOF
  echo -e "${RESET}"
}

pause() {
  echo
  read -rp "Press Enter to continue..." _
}

get_gost_version() {
  if command -v gost >/dev/null 2>&1; then
    gost -V 2>/dev/null | head -n1
    return 0
  fi
  return 1
}

check_gost_package_line() {
  local ver
  ver="$(get_gost_version)"
  if [[ -n "$ver" ]]; then
    echo -e "${BOLD}${PURPLE}GOST PACKAGE :${RESET} ${BOLD}${RED}${ver}${RESET}"
  else
    echo -e "${BOLD}${PURPLE}GOST PACKAGE :${RESET} ${BOLD}Not installed${RESET}"
  fi
}

service_state() {
  local svc="$1"
  systemctl is-active "$svc" 2>/dev/null
}

service_exists() {
  local svc="$1"
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$svc"
}

check_gost_service_line() {
  local in_svc="gost-in.service"
  local out_svc="gost-out.service"

  local in_exists=0 out_exists=0
  service_exists "$in_svc" && in_exists=1
  service_exists "$out_svc" && out_exists=1

  if ((in_exists==0 && out_exists==0)); then
    echo -e "${BOLD}${PURPLE}GOST Service :${RESET} ${BOLD}${PINK}Not Found Any${RESET}"
    return
  fi

  if ((in_exists==1 && out_exists==1)); then
    echo -e "${BOLD}${PURPLE}GOST Service :${RESET} ${BOLD}Multi Service gost Run!${RESET}"
    return
  fi

  if ((in_exists==1)); then
    local st
    st="$(service_state "$in_svc")"
    echo -e "${BOLD}${PURPLE}GOST Service :${RESET} ${BOLD}${PINK}GOST-IN${RESET} ${BOLD}${BLUE}${st^}${RESET}"
    return
  fi

  if ((out_exists==1)); then
    local st
    st="$(service_state "$out_svc")"
    echo -e "${BOLD}${PURPLE}GOST Service :${RESET} ${BOLD}${PINK}GOST-OUT${RESET} ${BOLD}${BLUE}${st^}${RESET}"
    return
  fi
}

render_status_block() {
  check_gost_package_line
  check_gost_service_line
  echo
}

render_footer() {
  echo
  echo -e "${BOLD}${CYAN}${FOOTER_TEXT}${RESET}"
}

read_choice() {
  local prompt="$1"
  local choice
  read -rp "$prompt" choice
  echo "$choice"
}

need_root() {
  if [[ $EUID -ne 0 ]]; then
    add_notice "${BOLD}${RED}Run script as root (sudo).${RESET}"
    echo -e "${BOLD}${RED}Error:${RESET} Please run as root: sudo ./yousafe.sh"
    pause
    return 1
  fi
  return 0
}

run_step() {
  local title="$1"
  shift
  echo -e "\n${BOLD}${CYAN}==> ${title}${RESET}"
  "$@"
  local code=$?
  if [[ $code -ne 0 ]]; then
    echo -e "${BOLD}${RED}!! Failed: ${title} (code=$code)${RESET}"
    add_notice "${BOLD}${RED}${title} failed (code=$code).${RESET}"
  else
    echo -e "${BOLD}${GREEN}OK: ${title}${RESET}"
    add_notice "${BOLD}${GREEN}${title} done.${RESET}"
  fi
  return $code
}

install_gost() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block

  echo -e "${BOLD}${YELLOW}Starting gost install...${RESET}"
  echo -e "${BOLD}${YELLOW}Logs:${RESET} /tmp/yousafe_install.log /tmp/yousafe_gost_install.log"
  echo

  run_step "Updating server packages (apt-get update)" \
    bash -c "apt-get update -y 2>&1 | tee /tmp/yousafe_install.log"

  run_step "Installing prerequisites (git, wget, curl)" \
    bash -c "apt-get install -y git wget curl 2>&1 | tee -a /tmp/yousafe_install.log"

  echo -e "${BOLD}${YELLOW}Select install source:${RESET}"
  echo -e "${BOLD}1 install gost from yourself${RESET}"
  echo -e "${BOLD}2 install from github${RESET}"
  echo

  local src_choice
  read -rp "Choose [1-2] (default 2): " src_choice
  [[ -z "$src_choice" ]] && src_choice="2"

  if [[ "$src_choice" == "2" ]]; then
    run_step "Running official GOST install script" \
      bash -c "bash <(curl -fsSL https://github.com/go-gost/gost/raw/master/install.sh) 2>&1 | tee /tmp/yousafe_gost_install.log"

  elif [[ "$src_choice" == "1" ]]; then
    local tar_path tmpdir

    read -rp "input binery file address (e.g. /root/gost.tar.gz): " tar_path
    if [[ -z "$tar_path" || ! -f "$tar_path" ]]; then
      add_notice "${BOLD}${RED}File not found: $tar_path${RESET}"
      echo -e "${BOLD}${RED}Error:${RESET} File not found."
      pause
      return 0
    fi

    tmpdir="/tmp/gost-self-install-$$"
    rm -rf "$tmpdir"
    mkdir -p "$tmpdir"

    run_step "Extracting gost archive" \
      bash -c "tar -xzf \"$tar_path\" -C \"$tmpdir\" 2>&1 | tee -a /tmp/yousafe_gost_install.log"

    if [[ -f "$tmpdir/gost" ]]; then
      run_step "Installing gost binary to /usr/local/bin/gost" \
        bash -c "chmod +x \"$tmpdir/gost\" && install -m 0755 \"$tmpdir/gost\" /usr/local/bin/gost 2>&1 | tee -a /tmp/yousafe_gost_install.log"
    else
      local found
      found="$(find "$tmpdir" -maxdepth 3 -type f -name gost 2>/dev/null | head -n1)"
      if [[ -n "$found" && -f "$found" ]]; then
        run_step "Installing gost binary to /usr/local/bin/gost" \
          bash -c "chmod +x \"$found\" && install -m 0755 \"$found\" /usr/local/bin/gost 2>&1 | tee -a /tmp/yousafe_gost_install.log"
      else
        add_notice "${BOLD}${RED}gost binary not found inside archive.${RESET}"
        echo -e "${BOLD}${RED}Error:${RESET} gost binary not found after extract."
        echo -e "${BOLD}${YELLOW}Tip:${RESET} Check extracted files: ls -lah \"$tmpdir\""
        rm -rf "$tmpdir"
        pause
        return 0
      fi
    fi

    rm -rf "$tmpdir" >/dev/null 2>&1 || true

    run_step "Checking gost version" \
      bash -c "/usr/local/bin/gost -V 2>&1 | tee -a /tmp/yousafe_gost_install.log"

  else
    add_notice "${BOLD}${RED}Invalid choice.${RESET}"
    echo -e "${BOLD}${RED}Error:${RESET} Invalid choice."
    pause
    return 0
  fi

  echo -e "\n${BOLD}${GREEN}DONE: GOST installation finished.${RESET}"
  add_notice "${BOLD}${GREEN}GOST installation finished.${RESET}"
  pause
}

uninstall_services_only() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block

  echo -e "${BOLD}${YELLOW}Uninstall ONLY services and configs...${RESET}"
  local log="/tmp/yousafe_uninstall_services_only.log"
  : > "$log"

  for svc in gost-in.service gost-out.service; do
    if service_exists "$svc"; then
      systemctl stop "$svc" >>"$log" 2>&1
      systemctl disable "$svc" >>"$log" 2>&1
    fi
  done

  rm -f /etc/systemd/system/gost-in.service /etc/systemd/system/gost-out.service \
        /lib/systemd/system/gost-in.service /lib/systemd/system/gost-out.service >>"$log" 2>&1

  systemctl daemon-reload >>"$log" 2>&1
  systemctl reset-failed >>"$log" 2>&1

  rm -rf /etc/gost-in /etc/gost-out >>"$log" 2>&1

  echo -e "\n${BOLD}${GREEN}DONE: Services & configs removed. gost binary kept.${RESET}"
  add_notice "${BOLD}${GREEN}Services & configs uninstalled (binary kept).${RESET}"
  pause
}

uninstall_menu() {
  while true; do
    clear_screen; render_banner; render_notices; echo; render_status_block
    echo -e "${BOLD}${CYAN}Uninstall Menu${RESET}\n"
    echo -e "${BOLD}1. Uninstall ONLY services & configs${RESET}"
    echo -e "${BOLD}2. Full uninstall (services + gost binary)${RESET}"
    echo -e "${BOLD}0. Back${RESET}"
    render_footer; echo

    local c
    c="$(read_choice "Select uninstall option: ")"
    case "$c" in
      1) uninstall_services_only ;;
      2) uninstall_gost ;;
      0) return 0 ;;
      *) add_notice "${BOLD}${RED}Invalid choice in Uninstall Menu.${RESET}" ;;
    esac
  done
}

uninstall_gost() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block

  echo -e "${BOLD}${YELLOW}Starting GOST uninstall...${RESET}"
  local log="/tmp/yousafe_gost_uninstall.log"
  : > "$log"

  for svc in gost-in.service gost-out.service; do
    if service_exists "$svc"; then
      systemctl stop "$svc" >>"$log" 2>&1
      systemctl disable "$svc" >>"$log" 2>&1
    fi
  done

  rm -f /etc/systemd/system/gost-in.service /etc/systemd/system/gost-out.service \
        /lib/systemd/system/gost-in.service /lib/systemd/system/gost-out.service >>"$log" 2>&1

  systemctl daemon-reload >>"$log" 2>&1
  systemctl reset-failed >>"$log" 2>&1

  rm -f /usr/local/bin/gost /usr/bin/gost /bin/gost >>"$log" 2>&1
  rm -rf /usr/local/share/gost /etc/gost /opt/gost >>"$log" 2>&1

  echo -e "\n${BOLD}${GREEN}DONE: GOST uninstall finished.${RESET}"
  add_notice "${BOLD}${GREEN}GOST uninstall finished.${RESET}"
  pause
}

ensure_zip_tools() {
  if ! command -v zip >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
    echo -e "${BOLD}${YELLOW}zip/unzip not found. Installing...${RESET}"
    apt-get update -y >/dev/null 2>&1
    apt-get install -y zip unzip >/dev/null 2>&1
  fi

  if ! command -v zip >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
    add_notice "${BOLD}${RED}Failed to install zip/unzip.${RESET}"
    echo -e "${BOLD}${RED}Error:${RESET} zip/unzip tools are required."
    pause
    return 1
  fi
  return 0
}

is_public_ipv4() {
  local ip="$1"
  [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 1

  IFS='.' read -r a b c d <<<"$ip"
  for oct in "$a" "$b" "$c" "$d"; do
    ((oct >=0 && oct <=255)) || return 1
  done

  [[ "$a" == "127" ]] && return 1
  [[ "$a" == "0" ]] && return 1

  [[ "$a" == "10" ]] && return 1
  [[ "$a" == "192" && "$b" == "168" ]] && return 1
  if [[ "$a" == "172" && "$b" =~ ^(1[6-9]|2[0-9]|3[0-1])$ ]]; then return 1; fi

  if [[ "$a" == "100" && "$b" -ge 64 && "$b" -le 127 ]]; then return 1; fi

  return 0
}

extract_public_ips_from_file() {
  local file="$1"
  [[ ! -f "$file" ]] && return 0

  grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$file" \
    | awk '!seen[$0]++' \
    | while read -r ip; do
        if is_public_ipv4 "$ip"; then
          echo "$ip"
        fi
      done
}

replace_ips_in_file() {
  local file="$1"; shift
  local new_ip="$1"; shift
  local -a old_ips=("$@")

  [[ ! -f "$file" ]] && return 0
  local old
  for old in "${old_ips[@]}"; do
    local esc_old="${old//./\\.}"
    sed -i "s/$esc_old/$new_ip/g" "$file"
  done
}

do_backup_side() {
  local side="$1"
  need_root || return 0
  ensure_zip_tools || return 0

  local ts backup_file tmpdir
  ts="$(date +%Y%m%d-%H%M%S)"
  backup_file="/root/backup-${ts}.zip"
  tmpdir="/tmp/yousafe-backup-${ts}"
  mkdir -p "$tmpdir"

  local json_src svc_src svc_src2
  if [[ "$side" == "IN" ]]; then
    json_src="/etc/gost-in/gost-in.json"
    svc_src="/etc/systemd/system/gost-in.service"
    svc_src2="/lib/systemd/system/gost-in.service"
  else
    json_src="/etc/gost-out/gost-out.json"
    svc_src="/etc/systemd/system/gost-out.service"
    svc_src2="/lib/systemd/system/gost-out.service"
  fi

  [[ ! -f "$json_src" ]] && {
    add_notice "${BOLD}${RED}Config not found: $json_src${RESET}"
    echo -e "${BOLD}${RED}Error:${RESET} $json_src not found."
    rm -rf "$tmpdir"
    pause
    return 0
  }

  cp -f "$json_src" "$tmpdir/"

  if [[ -f "$svc_src" ]]; then
    cp -f "$svc_src" "$tmpdir/"
  elif [[ -f "$svc_src2" ]]; then
    cp -f "$svc_src2" "$tmpdir/"
  fi

  ( cd "$tmpdir" && zip -r "$backup_file" . >/dev/null 2>&1 )

  rm -rf "$tmpdir"

  echo -e "\n${BOLD}${GREEN}Backup created:${RESET} ${BOLD}${CYAN}$backup_file${RESET}"
  add_notice "${BOLD}${GREEN}Backup created: $backup_file${RESET}"
  pause
}

do_restore_side() {
  local side="$1"
  need_root || return 0
  ensure_zip_tools || return 0

  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}Restore gost-${side} from backup${RESET}\n"

  local zip_path
  read -rp "Enter backup zip path (default search /root/backup-*.zip): " zip_path
  if [[ -z "$zip_path" ]]; then
    zip_path="$(ls -1t /root/backup-*.zip 2>/dev/null | head -n1)"
  fi
  [[ -z "$zip_path" || ! -f "$zip_path" ]] && {
    add_notice "${BOLD}${RED}Backup zip not found.${RESET}"
    echo -e "${BOLD}${RED}Error:${RESET} Backup zip not found."
    pause
    return 0
  }

  local ts tmpdir
  ts="$(date +%Y%m%d-%H%M%S)"
  tmpdir="/tmp/yousafe-restore-${ts}"
  mkdir -p "$tmpdir"

  unzip -o "$zip_path" -d "$tmpdir" >/dev/null 2>&1 || {
    add_notice "${BOLD}${RED}Failed to unzip backup.${RESET}"
    echo -e "${BOLD}${RED}Error:${RESET} Failed to unzip."
    rm -rf "$tmpdir"
    pause
    return 0
  }

  local json_file svc_file
  if [[ "$side" == "IN" ]]; then
    json_file="$tmpdir/gost-in.json"
    svc_file="$tmpdir/gost-in.service"
  else
    json_file="$tmpdir/gost-out.json"
    svc_file="$tmpdir/gost-out.service"
  fi

  [[ ! -f "$json_file" ]] && {
    add_notice "${BOLD}${RED}Backup missing $json_file.${RESET}"
    echo -e "${BOLD}${RED}Error:${RESET} Backup missing config for gost-$side."
    rm -rf "$tmpdir"
    pause
    return 0
  }

  local -a pub_ips=()
  while read -r ip; do
    [[ -n "$ip" ]] && pub_ips+=("$ip")
  done < <(extract_public_ips_from_file "$json_file")

  if ((${#pub_ips[@]} > 0)); then
    local uniq_tmp=""
    uniq_tmp="$(printf "%s\n" "${pub_ips[@]}" | awk '!seen[$0]++')"
    mapfile -t pub_ips <<<"$uniq_tmp"
  fi

  if ((${#pub_ips[@]} > 0)); then
    echo -e "${BOLD}${YELLOW}Public IPs found in backup:${RESET}"
    printf "  - %s\n" "${pub_ips[@]}"
    echo

    local ans
    read -rp "Replace ALL these public IPs with a new IP? (y/N): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      local new_ip
      read -rp "Enter NEW public IP: " new_ip
      if ! is_public_ipv4 "$new_ip"; then
        add_notice "${BOLD}${RED}Invalid public IP entered.${RESET}"
        echo -e "${BOLD}${RED}Error:${RESET} Invalid public IP."
        rm -rf "$tmpdir"
        pause
        return 0
      fi

      replace_ips_in_file "$json_file" "$new_ip" "${pub_ips[@]}"
      [[ -f "$svc_file" ]] && replace_ips_in_file "$svc_file" "$new_ip" "${pub_ips[@]}"

      add_notice "${BOLD}${GREEN}Public IPs replaced with $new_ip.${RESET}"
    fi
  else
    echo -e "${BOLD}${YELLOW}No public IPs detected in backup (skipping replace).${RESET}\n"
  fi

  local dest_dir dest_json dest_svc
  if [[ "$side" == "IN" ]]; then
    dest_dir="/etc/gost-in"
    dest_json="$dest_dir/gost-in.json"
    dest_svc="/etc/systemd/system/gost-in.service"
  else
    dest_dir="/etc/gost-out"
    dest_json="$dest_dir/gost-out.json"
    dest_svc="/etc/systemd/system/gost-out.service"
  fi
  ensure_dir "$dest_dir"

  cp -f "$json_file" "$dest_json"

  if [[ -f "$svc_file" ]]; then
    cp -f "$svc_file" "$dest_svc"
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$(basename "$dest_svc")" >/dev/null 2>&1
    systemctl restart "$(basename "$dest_svc")" >/dev/null 2>&1
  else
    systemctl daemon-reload >/dev/null 2>&1
    systemctl restart "gost-${side,,}.service" >/dev/null 2>&1
  fi

  rm -rf "$tmpdir"

  echo -e "\n${BOLD}${GREEN}RESTORE DONE for gost-${side}.${RESET}"
  add_notice "${BOLD}${GREEN}Restore done for gost-${side}.${RESET}"
  pause
}

backup_menu() {
  while true; do
    clear_screen; render_banner; render_notices; echo; render_status_block
    echo -e "${BOLD}${CYAN}Backup Menu${RESET}\n"
    echo -e "${BOLD}1. backup of GOST-IN${RESET}"
    echo -e "${BOLD}2. backup of GOST-OUT${RESET}"
    echo -e "${BOLD}0. Back${RESET}"
    render_footer; echo

    local c
    c="$(read_choice "Select backup option: ")"
    case "$c" in
      1) do_backup_side "IN" ;;
      2) do_backup_side "OUT" ;;
      0) return 0 ;;
      *) add_notice "${BOLD}${RED}Invalid choice in Backup Menu.${RESET}" ;;
    esac
  done
}

restore_menu() {
  while true; do
    clear_screen; render_banner; render_notices; echo; render_status_block
    echo -e "${BOLD}${CYAN}Restore Menu${RESET}\n"
    echo -e "${BOLD}1. restore of GOST-IN${RESET}"
    echo -e "${BOLD}2. restore of GOST-OUT${RESET}"
    echo -e "${BOLD}0. Back${RESET}"
    render_footer; echo

    local c
    c="$(read_choice "Select restore option: ")"
    case "$c" in
      1) do_restore_side "IN" ;;
      2) do_restore_side "OUT" ;;
      0) return 0 ;;
      *) add_notice "${BOLD}${RED}Invalid choice in Restore Menu.${RESET}" ;;
    esac
  done
}

backup_restore_menu() {
  while true; do
    clear_screen; render_banner; render_notices; echo; render_status_block
    echo -e "${BOLD}${CYAN}Backup - Restore${RESET}\n"
    echo -e "${BOLD}1. backup${RESET}"
    echo -e "${BOLD}2. restore${RESET}"
    echo -e "${BOLD}0. Back${RESET}"
    render_footer; echo

    local c
    c="$(read_choice "Select: ")"
    case "$c" in
      1) backup_menu ;;
      2) restore_menu ;;
      0) return 0 ;;
      *) add_notice "${BOLD}${RED}Invalid choice in Backup-Restore Menu.${RESET}" ;;
    esac
  done
}

get_gost_bin() {
  local bin
  bin="$(command -v gost 2>/dev/null)"
  [[ -z "$bin" ]] && echo "/usr/local/bin/gost" || echo "$bin"
}

ensure_dir() { [[ -d "$1" ]] || mkdir -p "$1"; }

normalize_path() {
  local p="$1"
  [[ -z "$p" ]] && p="/tunnel"
  [[ "$p" != /* ]] && p="/$p"
  echo "$p"
}

parse_ports() {
  local input="$1"
  local -a ports=()
  local token start end i

  input="${input// /}"
  IFS=',' read -ra parts <<<"$input"

  for token in "${parts[@]}"; do
    if [[ "$token" =~ ^[0-9]+-[0-9]+$ ]]; then
      start="${token%-*}"
      end="${token#*-}"
      if ((start <= end)); then
        for ((i=start; i<=end; i++)); do ports+=("$i"); done
      else
        for ((i=start; i>=end; i--)); do ports+=("$i"); done
      fi
    elif [[ "$token" =~ ^[0-9]+$ ]]; then
      ports+=("$token")
    fi
  done

  printf "%s\n" "${ports[@]}" | awk '!seen[$0]++' | sort -n
}

write_atomic() {
  local file="$1"
  local tmp="${file}.tmp.$$"
  cat >"$tmp" && mv "$tmp" "$file"
}

remove_service_if_exists() {
  local svc="$1"
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$svc"; then
    systemctl stop "$svc" >/dev/null 2>&1
    systemctl disable "$svc" >/dev/null 2>&1
    rm -f "/etc/systemd/system/$svc" "/lib/systemd/system/$svc" >/dev/null 2>&1
    systemctl daemon-reload >/dev/null 2>&1
  fi
}

install_service_unit() {
  local svc="$1"
  local config_path="$2"
  local bin
  bin="$(get_gost_bin)"

  cat <<EOF >/etc/systemd/system/$svc
[Unit]
Description=YOUSAFE GOST Service
[Service]
Type=simple
ExecStart=$bin -C $config_path
Restart=always
RestartSec=3
LimitNOFILE=2048576
LimitNPROC=150000
TimeoutSec=600
Nice=-10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable "$svc" >/dev/null 2>&1
  systemctl restart "$svc" >/dev/null 2>&1
}


ws_direct_oneone_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}WS Direct OneOne (gost-IN)${RESET}\n"

  local out_ip tunnel_port tunnel_path user pass forwards
  read -rp "OUT server IP address: " out_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Tunnel Path: " tunnel_path
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "Forwards Port(s): " forwards

  tunnel_path="$(normalize_path "$tunnel_path")"
  [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing required inputs.${RESET}"; pause; return 0; }

  local -a ports
  mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid forward ports.${RESET}"; pause; return 0; }

  local services_json=""
  local i p last_index=$(( ${#ports[@]} - 1 ))

  for i in "${!ports[@]}"; do
    p="${ports[$i]}"

    services_json+=$(cat <<EOF
    {
      "name": "public-$p",
      "addr": ":$p",
      "handler": {
        "type": "tcp",
        "chain": "to-b-relay"
      },
      "listener": {
        "type": "tcp"
      },
      "forwarder": {
        "nodes": [
          {
            "name": "gost-b-$p",
            "addr": "127.0.0.1:$p"
          }
        ]
      }
    }
EOF
)

    if (( i < last_index )); then
      services_json+=","
    fi
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],

  "chains": [
    {
      "name": "to-b-relay",
      "hops": [
        {
          "name": "hop-0",
          "nodes": [
            {
              "name": "relay-b-ws",
              "addr": "$out_ip:$tunnel_port",
              "connector": {
                "type": "relay",
                "auth": {
                  "username": "$user",
                  "password": "$pass"
                }
              },
              "dialer": {
                "type": "ws",
                "metadata": {
                  "path": "$tunnel_path",
                  "host": "$out_ip"
                }
              }
            }
          ]
        }
      ]
    }
  ],

  "log": {
    "level": "error",
    "format": "text",
    "output": "stderr"
  }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: WS Direct OneOne gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}WS Direct OneOne gost-IN configured.${RESET}"
  pause
}

ws_direct_oneone_out() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}WS Direct OneOne (gost-OUT)${RESET}\n"

  local in_ip tunnel_port tunnel_path user pass
  read -rp "gost-IN IP address: " in_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Tunnel Path: " tunnel_path
  read -rp "Username: " user
  read -rp "Password: " pass

  tunnel_path="$(normalize_path "$tunnel_path")"
  [[ -z "$in_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" ]] && {
    add_notice "${BOLD}${RED}Missing required inputs.${RESET}"; pause; return 0; }

  local config_dir="/etc/gost-out"
  local config_path="$config_dir/gost-out.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
    {
      "name": "relay-ws-$tunnel_port",
      "addr": ":$tunnel_port",
      "admission": "only-a",
      "handler": {
        "type": "relay",
        "auther": "relay-auth"
      },
      "listener": {
        "type": "ws",
        "metadata": {
          "path": "$tunnel_path"
        }
      }
    }
  ],

  "admissions": [
    {
      "name": "only-a",
      "whitelist": true,
      "matchers": [
        "$in_ip"
      ]
    }
  ],

  "authers": [
    {
      "name": "relay-auth",
      "auths": [
        {
          "username": "$user",
          "password": "$pass"
        }
      ]
    }
  ],

  "log": {
    "level": "error",
    "format": "text",
    "output": "stderr"
  }
}
EOF

  remove_service_if_exists "gost-out.service"
  install_service_unit "gost-out.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: WS Direct OneOne gost-OUT configured.${RESET}"
  add_notice "${BOLD}${GREEN}WS Direct OneOne gost-OUT configured.${RESET}"
  pause
}

ws_direct_multiout_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}WS Direct MultiOut (gost-IN)${RESET}\n"

  local out_count
  read -rp "How much OUT? " out_count
  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 ]] && {
    add_notice "${BOLD}${RED}Invalid OUT count.${RESET}"; pause; return 0; }

  local -a chains_blocks=()
  local -a service_blocks=()
  local letters=(b c d e f g h i j k l m n o p)

  local i out_ip tunnel_port tunnel_path user pass forwards
  for ((i=1; i<=out_count; i++)); do
    local L="${letters[$((i-1))]}"
    echo -e "${BOLD}${YELLOW}\n--- OUT $i (${L}) ---${RESET}"

    read -rp "Gost Out $i IP: " out_ip
    read -rp "Gost Out $i Tunnel Port: " tunnel_port
    read -rp "Gost Out $i Tunnel Path: " tunnel_path
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass
    read -rp "Forwards Port(s) for Out $i: " forwards

    tunnel_path="$(normalize_path "$tunnel_path")"
    [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    chains_blocks+=("$(cat <<EOF
    {
      "name": "to-$L-relay",
      "hops": [
        {
          "name": "hop-$L",
          "nodes": [
            {
              "name": "relay-$L-ws",
              "addr": "$out_ip:$tunnel_port",
              "connector": {
                "type": "relay",
                "auth": {
                  "username": "$user",
                  "password": "$pass"
                }
              },
              "dialer": {
                "type": "ws",
                "metadata": {
                  "path": "$tunnel_path",
                  "host": "$out_ip"
                }
              }
            }
          ]
        }
      ]
    }
EOF
)")

    local -a ports=()
    mapfile -t ports < <(parse_ports "$forwards")
    ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports for Out $i.${RESET}"; pause; return 0; }

    local p
    for p in "${ports[@]}"; do
      service_blocks+=("$(cat <<EOF
    {
      "name": "to-$L-$p",
      "addr": ":$p",
      "handler": { "type": "tcp", "chain": "to-$L-relay" },
      "listener": { "type": "tcp" },
      "forwarder": {
        "nodes": [
          { "name": "$L-gost-$p", "addr": "127.0.0.1:$p" }
        ]
      }
    }
EOF
)")
    done
  done

  local services_json="" last_s=$(( ${#service_blocks[@]} - 1 ))
  for i in "${!service_blocks[@]}"; do
    services_json+="${service_blocks[$i]}"
    (( i < last_s )) && services_json+=","
    services_json+=$'\n'
  done

  local chains_json="" last_c=$(( ${#chains_blocks[@]} - 1 ))
  for i in "${!chains_blocks[@]}"; do
    chains_json+="${chains_blocks[$i]}"
    (( i < last_c )) && chains_json+=","
    chains_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],

  "chains": [
$chains_json
  ],

  "log": { "level": "error", "format": "text", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: WS Direct MultiOut gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}WS Direct MultiOut gost-IN configured.${RESET}"
  pause
}

ws_direct_multiout_out() { ws_direct_oneone_out; }

ws_direct_lb_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}WS Direct Loadbalancer (gost-IN)${RESET}\n"

  local out_count forwards
  read -rp "How much OUT? " out_count
  read -rp "Forward ports: " forwards
  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 ]] && {
    add_notice "${BOLD}${RED}Invalid OUT count.${RESET}"; pause; return 0; }
  [[ -z "$forwards" ]] && { add_notice "${BOLD}${RED}Missing forward ports.${RESET}"; pause; return 0; }

  local -a ports; mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local letters=(B C D E F G H I J K)
  local -a node_blocks=()
  local i out_ip tunnel_port tunnel_path user pass ttl

  for ((i=1; i<=out_count; i++)); do
    local L="${letters[$((i-1))]}"
    echo -e "${BOLD}${YELLOW}\n--- OUT $i (to-$L) ---${RESET}"
    read -rp "Gost Out $i IP: " out_ip
    read -rp "Gost Out $i Tunnel Port: " tunnel_port
    read -rp "Gost Out $i Tunnel Path: " tunnel_path
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass
    read -rp "TTL seconds (5-120): " ttl

    tunnel_path="$(normalize_path "$tunnel_path")"
    [[ -z "$ttl" || ! "$ttl" =~ ^[0-9]+$ || "$ttl" -lt 5 || "$ttl" -gt 120 ]] && ttl=15
    [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    node_blocks+=("$(cat <<EOF
            {
              "name": "to-$L",
              "addr": "$out_ip:$tunnel_port",
              "connector": {
                "type": "relay",
                "auth": { "username": "$user", "password": "$pass" }
              },
              "dialer": {
                "type": "ws",
                "metadata": {
                  "path": "$tunnel_path",
                  "keepAlive": true,
                  "ttl": "${ttl}s"
                }
              }
            }
EOF
)")
  done

  local nodes_json="" last_n=$(( ${#node_blocks[@]} - 1 ))
  for i in "${!node_blocks[@]}"; do
    nodes_json+="${node_blocks[$i]}"
    (( i < last_n )) && nodes_json+=","
    nodes_json+=$'\n'
  done

  local -a service_blocks=()
  local p
  for p in "${ports[@]}"; do
    service_blocks+=("$(cat <<EOF
    {
      "name": "public-$p",
      "addr": ":$p",
      "handler": {
        "type": "tcp",
        "chain": "to-backends"
      },
      "listener": {
        "type": "tcp"
      },
      "forwarder": {
        "nodes": [
          { "name": "dst-$p", "addr": "127.0.0.1:$p" }
        ]
      }
    }
EOF
)")
  done

  local services_json="" last_s=$(( ${#service_blocks[@]} - 1 ))
  for i in "${!service_blocks[@]}"; do
    services_json+="${service_blocks[$i]}"
    (( i < last_s )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],

  "chains": [
    {
      "name": "to-backends",
      "selector": {
        "strategy": "round",
        "maxFails": 1,
        "failTimeout": "10s"
      },
      "hops": [
        {
          "name": "hop-0",
          "nodes": [
$nodes_json
          ]
        }
      ]
    }
  ],

  "log": {
    "level": "error",
    "format": "json",
    "output": "stderr"
  }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: WS Direct Loadbalancer gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}WS Direct Loadbalancer gost-IN configured.${RESET}"
  pause
}

ws_direct_lb_out() { ws_direct_oneone_out; }

ws_reverse_oneone_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}WS Reverse OneOne (gost-IN)${RESET}\n"

  local out_ip tunnel_port tunnel_path user pass
  read -rp "Gost-OUT IP address: " out_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Tunnel Path: " tunnel_path
  read -rp "Username: " user
  read -rp "Password: " pass

  tunnel_path="$(normalize_path "$tunnel_path")"
  [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
    {
      "name": "relay-ws-bind",
      "addr": ":$tunnel_port",
      "admission": "admission-b-only",
      "handler": {
        "type": "relay",
        "auth": {
          "username": "$user",
          "password": "$pass"
        },
        "metadata": {
          "bind": true
        }
      },
      "listener": {
        "type": "ws",
        "metadata": {
          "path": "$tunnel_path",
          "backlog": 8192
        }
      }
    }
  ],
  "admissions": [
    {
      "name": "admission-b-only",
      "whitelist": true,
      "matchers": [
        "$out_ip"
      ]
    }
  ],
  "log": {
    "level": "info",
    "format": "text",
    "output": "stderr"
  }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: WS Reverse OneOne gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}WS Reverse OneOne gost-IN configured.${RESET}"
  pause
}

ws_reverse_oneone_out() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}WS Reverse OneOne (gost-OUT)${RESET}\n"

  local in_ip tunnel_port tunnel_path user pass ttl forwards
  read -rp "gost-IN IP address: " in_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Tunnel Path: " tunnel_path
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "TTL seconds (5-120): " ttl
  read -rp "Forwards Port(s): " forwards

  tunnel_path="$(normalize_path "$tunnel_path")"
  [[ -z "$ttl" || ! "$ttl" =~ ^[0-9]+$ || "$ttl" -lt 5 || "$ttl" -gt 120 ]] && ttl=15
  [[ -z "$in_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports; mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local -a blocks=()
  local p
  for p in "${ports[@]}"; do
    blocks+=("$(cat <<EOF
    {
      "name": "rtcp-$p",
      "addr": ":$p",
      "handler": {
        "type": "rtcp"
      },
      "listener": {
        "type": "rtcp",
        "chain": "chain-to-a-ws-relay"
      },
      "forwarder": {
        "nodes": [
          {
            "name": "gost-$p",
            "addr": "127.0.0.1:$p"
          }
        ]
      }
    }
EOF
)")
  done

  local services_json="" last_b=$(( ${#blocks[@]} - 1 ))
  for i in "${!blocks[@]}"; do
    services_json+="${blocks[$i]}"
    (( i < last_b )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-out"
  local config_path="$config_dir/gost-out.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
    {
      "name": "chain-to-a-ws-relay",
      "hops": [
        {
          "name": "hop-0",
          "nodes": [
            {
              "name": "node-to-a-ws",
              "addr": "$in_ip:$tunnel_port",
              "connector": {
                "type": "relay",
                "auth": {
                  "username": "$user",
                  "password": "$pass"
                }
              },
              "dialer": {
                "type": "ws",
                "metadata": {
                  "path": "$tunnel_path",
                  "keepAlive": true,
                  "ttl": "${ttl}s"
                }
              }
            }
          ]
        }
      ]
    }
  ],
  "log": {
    "level": "info",
    "format": "text",
    "output": "stderr"
  }
}
EOF

  remove_service_if_exists "gost-out.service"
  install_service_unit "gost-out.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: WS Reverse OneOne gost-OUT configured.${RESET}"
  add_notice "${BOLD}${GREEN}WS Reverse OneOne gost-OUT configured.${RESET}"
  pause
}

ws_reverse_multiout_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}WS Reverse MultiOut (gost-IN)${RESET}\n"

  local out_count tunnel_port tunnel_path
  read -rp "How much gost-OUT? " out_count
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Tunnel Path: " tunnel_path

  tunnel_path="$(normalize_path "$tunnel_path")"
  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 || -z "$tunnel_port" ]] && {
    add_notice "${BOLD}${RED}Invalid inputs.${RESET}"; pause; return 0; }

  local -a matchers=()
  local -a auths=()
  local letters=(b c d e f g h i j k)

  local i ip user pass
  for ((i=1; i<=out_count; i++)); do
    echo -e "${BOLD}${YELLOW}\n--- OUT $i (${letters[$((i-1))]}) ---${RESET}"
    read -rp "Gost Out $i IP address: " ip
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass

    [[ -z "$ip" || -z "$user" || -z "$pass" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    matchers+=("        \"$ip\"")
    auths+=("        { \"username\": \"$user\", \"password\": \"$pass\" }")
  done

  local matchers_json="" auths_json=""
  local last_m=$(( ${#matchers[@]} - 1 ))
  local last_a=$(( ${#auths[@]} - 1 ))

  for i in "${!matchers[@]}"; do
    matchers_json+="${matchers[$i]}"
    (( i < last_m )) && matchers_json+=","
    matchers_json+=$'\n'
  done

  for i in "${!auths[@]}"; do
    auths_json+="${auths[$i]}"
    (( i < last_a )) && auths_json+=","
    auths_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
    {
      "name": "relay-ws-bind-$tunnel_port",
      "addr": ":$tunnel_port",
      "admission": "only-b-and-c",
      "handler": {
        "type": "relay",
        "auther": "backends-auth",
        "metadata": {
          "bind": true
        }
      },
      "listener": {
        "type": "ws",
        "metadata": {
          "path": "$tunnel_path",
          "backlog": 8192
        }
      }
    }
  ],

  "admissions": [
    {
      "name": "only-b-and-c",
      "whitelist": true,
      "matchers": [
$matchers_json
      ]
    }
  ],

  "authers": [
    {
      "name": "backends-auth",
      "auths": [
$auths_json
      ]
    }
  ],

  "log": {
    "level": "info",
    "format": "text",
    "output": "stderr"
  }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: WS Reverse MultiOut gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}WS Reverse MultiOut gost-IN configured.${RESET}"
  pause
}

ws_reverse_multiout_out() { ws_reverse_oneone_out; }

ws_reverse_lb_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}WS Reverse Loadbalancer (gost-IN)${RESET}\n"

  local out_count tunnel_port tunnel_path forwards local_user local_pass ttl
  read -rp "How much gost-OUT? " out_count
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Tunnel Path: " tunnel_path
  read -rp "Forward ports: " forwards
  read -rp "Local username: " local_user
  read -rp "Local password: " local_pass
  read -rp "TTL seconds (5-120): " ttl

  tunnel_path="$(normalize_path "$tunnel_path")"
  [[ -z "$ttl" || ! "$ttl" =~ ^[0-9]+$ || "$ttl" -lt 5 || "$ttl" -gt 120 ]] && ttl=15
  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 || -z "$tunnel_port" ]] && {
    add_notice "${BOLD}${RED}Invalid inputs.${RESET}"; pause; return 0; }
  [[ -z "$forwards" || -z "$local_user" || -z "$local_pass" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports; mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local -a matchers=("        \"127.0.0.1\"")
  local -a auths=()
  local letters=(b c d e f g h)

  local i ip user pass
  for ((i=1; i<=out_count; i++)); do
    echo -e "${BOLD}${YELLOW}\n--- OUT $i (${letters[$((i-1))]}) ---${RESET}"
    read -rp "Gost Out $i IP address: " ip
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass

    [[ -z "$ip" || -z "$user" || -z "$pass" ]] && {
      add_notice "${BOLD}${RED}Missing inputs. Out $i.${RESET}"; pause; return 0; }

    matchers+=("        \"$ip\"")
    auths+=("        { \"username\": \"$user\", \"password\": \"$pass\" }")
  done

  auths+=("        { \"username\": \"$local_user\", \"password\": \"$local_pass\" }")

  local matchers_json="" auths_json=""
  local last_m=$(( ${#matchers[@]} - 1 ))
  local last_a=$(( ${#auths[@]} - 1 ))

  for i in "${!matchers[@]}"; do
    matchers_json+="${matchers[$i]}"
    (( i < last_m )) && matchers_json+=","
    matchers_json+=$'\n'
  done

  for i in "${!auths[@]}"; do
    auths_json+="${auths[$i]}"
    (( i < last_a )) && auths_json+=","
    auths_json+=$'\n'
  done

  local -a service_blocks=()
  local p
  for p in "${ports[@]}"; do
    service_blocks+=("$(cat <<EOF
    {
      "name": "public-$p",
      "addr": ":$p",
      "handler": { "type": "tcp", "chain": "to-tunnel" },
      "listener": { "type": "tcp" }
    }
EOF
)")
  done

  local services_json="" last_s=$(( ${#service_blocks[@]} - 1 ))
  for i in "${!service_blocks[@]}"; do
    services_json+="${service_blocks[$i]}"
    (( i < last_s )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
    {
      "name": "tunnel-server-ws-$tunnel_port",
      "addr": ":$tunnel_port",
      "admission": "only-bc",
      "handler": {
        "type": "tunnel",
        "auther": "backends-auth",
        "metadata": {
          "tunnel.direct": true
        }
      },
      "listener": {
        "type": "ws",
        "metadata": { "path": "$tunnel_path" }
      }
    },

$services_json
  ],

  "chains": [
    {
      "name": "to-tunnel",
      "hops": [
        {
          "name": "hop-0",
          "nodes": [
            {
              "name": "tunnel-local",
              "addr": "127.0.0.1:$tunnel_port",
              "connector": {
                "type": "tunnel",
                "auth": { "username": "$local_user", "password": "$local_pass" },
                "metadata": {
                  "tunnel.id": "11111111-1111-1111-1111-111111111111"
                }
              },
              "dialer": {
                "type": "ws",
                "metadata": {
                  "path": "$tunnel_path",
                  "keepAlive": true,
                  "ttl": "${ttl}s"
                }
              }
            }
          ]
        }
      ]
    }
  ],

  "admissions": [
    {
      "name": "only-bc",
      "whitelist": true,
      "matchers": [
$matchers_json
      ]
    }
  ],

  "authers": [
    {
      "name": "backends-auth",
      "auths": [
$auths_json
      ]
    }
  ],

  "log": {
    "level": "error",
    "format": "text",
    "output": "stderr"
  }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: WS Reverse Loadbalancer gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}WS Reverse Loadbalancer gost-IN configured.${RESET}"
  pause
}

ws_reverse_lb_out() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}WS Reverse Loadbalancer (gost-OUT)${RESET}\n"

  local in_ip tunnel_port tunnel_path user pass ttl forwards backend_index
  read -rp "gost-IN IP address: " in_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Tunnel Path: " tunnel_path
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "TTL seconds (5-120): " ttl
  read -rp "Forwards Port(s): " forwards
  read -rp "This OUT backend index? (1=b,2=c,3=d...): " backend_index

  tunnel_path="$(normalize_path "$tunnel_path")"
  [[ -z "$ttl" || ! "$ttl" =~ ^[0-9]+$ || "$ttl" -lt 5 || "$ttl" -gt 120 ]] && ttl=15
  [[ -z "$backend_index" || ! "$backend_index" =~ ^[0-9]+$ ]] && backend_index=1
  local letters=(b c d e f g h)
  local L="${letters[$((backend_index-1))]}"
  [[ -z "$L" ]] && L="b"

  [[ -z "$in_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports; mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local -a blocks=(); local p
  for p in "${ports[@]}"; do
    blocks+=("$(cat <<EOF
    {
      "name": "gost-$p",
      "addr": ":0",
      "handler": { "type": "rtcp" },
      "listener": { "type": "rtcp", "chain": "to-a" },
      "forwarder": {
        "nodes": [
          { "name": "local-$p", "addr": "127.0.0.1:$p" }
        ]
      }
    }
EOF
)")
  done

  local services_json="" last_b=$(( ${#blocks[@]} - 1 ))
  for i in "${!blocks[@]}"; do
    services_json+="${blocks[$i]}"
    (( i < last_b )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-out"
  local config_path="$config_dir/gost-out.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],

  "chains": [
    {
      "name": "to-a",
      "hops": [
        {
          "name": "hop-0",
          "nodes": [
            {
              "name": "tunnel-client-$L",
              "addr": "$in_ip:$tunnel_port",
              "connector": {
                "type": "tunnel",
                "auth": { "username": "$user", "password": "$pass" },
                "metadata": {
                  "tunnel.id": "11111111-1111-1111-1111-111111111111",
                  "tunnel.weight": 1
                }
              },
              "dialer": {
                "type": "ws",
                "metadata": {
                  "path": "$tunnel_path",
                  "keepAlive": true,
                  "ttl": "${ttl}s"
                }
              }
            }
          ]
        }
      ]
    }
  ],

  "log": {
    "level": "error",
    "format": "text",
    "output": "stderr"
  }
}
EOF

  remove_service_if_exists "gost-out.service"
  install_service_unit "gost-out.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: WS Reverse Loadbalancer gost-OUT configured.${RESET}"
  add_notice "${BOLD}${GREEN}WS Reverse Loadbalancer gost-OUT configured.${RESET}"
  pause
}




tcp_direct_oneone_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}TCP Direct OneOne (gost-IN)${RESET}\n"

  local out_ip tunnel_port user pass forwards
  read -rp "OUT server IP address: " out_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "Forwards Port(s): " forwards

  [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports
  mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local services_json=""
  local i p last_index=$(( ${#ports[@]} - 1 ))

  for i in "${!ports[@]}"; do
    p="${ports[$i]}"
    services_json+=$(cat <<EOF
    {
      "name": "public-$p",
      "addr": ":$p",
      "handler": { "type": "tcp", "chain": "to-B" },
      "listener": { "type": "tcp" },
      "forwarder": { "nodes": [ { "name": "gost-x-$p", "addr": "127.0.0.1:$p" } ] }
    }
EOF
)
    if (( i < last_index )); then
      services_json+=","
    fi
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
    {
      "name": "to-B",
      "hops": [
        { "name": "hop-b", "nodes": [
            {
              "name": "relay-B",
              "addr": "$out_ip:$tunnel_port",
              "connector": { "type": "relay", "auth": { "username": "$user", "password": "$pass" } },
              "dialer": { "type": "tcp" }
            }
        ] }
      ]
    }
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: TCP Direct OneOne gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}TCP Direct OneOne gost-IN configured.${RESET}"
  pause
}

tcp_direct_oneone_out() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}TCP Direct OneOne (gost-OUT)${RESET}\n"

  local in_ip tunnel_port user pass
  read -rp "gost-IN IP address: " in_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass

  [[ -z "$in_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local config_dir="/etc/gost-out"
  local config_path="$config_dir/gost-out.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
    { "name": "relay-tcp-$tunnel_port", "addr": ":$tunnel_port", "admission": "only-a",
      "handler": { "type": "relay", "auther": "relay-auth" }, "listener": { "type": "tcp" } }
  ],
  "admissions": [
    { "name": "only-a", "whitelist": true, "matchers": [ "127.0.0.1", "::1", "$in_ip" ] }
  ],
  "authers": [
    { "name": "relay-auth", "auths": [ { "username": "$user", "password": "$pass" } ] }
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-out.service"
  install_service_unit "gost-out.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: TCP Direct OneOne gost-OUT configured.${RESET}"
  add_notice "${BOLD}${GREEN}TCP Direct OneOne gost-OUT configured.${RESET}"
  pause
}

tcp_direct_multiout_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}TCP Direct MultiOut (gost-IN)${RESET}\n"

  local out_count
  read -rp "How much OUT? " out_count
  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 ]] && {
    add_notice "${BOLD}${RED}Invalid OUT count.${RESET}"; pause; return 0; }

  local -a chains_blocks=()
  local -a service_blocks=()

  local i out_ip tunnel_port user pass forwards
  for ((i=1; i<=out_count; i++)); do
    echo -e "${BOLD}${YELLOW}\n--- OUT $i ---${RESET}"
    read -rp "Gost Out $i IP: " out_ip
    read -rp "Gost Out $i Tunnel Port: " tunnel_port
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass
    read -rp "Forwards Port(s) for Out $i: " forwards

    [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    local chain_name="to-gost${i}-out"
    chains_blocks+=("$(cat <<EOF
    {
      "name": "$chain_name",
      "hops": [
        { "name": "hop-gost$i", "nodes": [
          {
            "name": "relay-gost$i-tcp",
            "addr": "$out_ip:$tunnel_port",
            "connector": { "type": "relay", "auth": { "username": "$user", "password": "$pass" } },
            "dialer": { "type": "tcp" }
          }
        ] }
      ]
    }
EOF
)")

    local -a ports=()
    mapfile -t ports < <(parse_ports "$forwards")
    ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports for Out $i.${RESET}"; pause; return 0; }

    local p
    for p in "${ports[@]}"; do
      service_blocks+=("$(cat <<EOF
    {
      "name": "public-$p-to-gost$i",
      "addr": ":$p",
      "handler": { "type": "tcp", "chain": "$chain_name" },
      "listener": { "type": "tcp" },
      "forwarder": { "nodes": [ { "name": "gost-$i-$p", "addr": "127.0.0.1:$p" } ] }
    }
EOF
)")
    done
  done

  local services_json="" last_s=$(( ${#service_blocks[@]} - 1 ))
  for i in "${!service_blocks[@]}"; do
    services_json+="${service_blocks[$i]}"
    (( i < last_s )) && services_json+=","
    services_json+=$'\n'
  done

  local chains_json="" last_c=$(( ${#chains_blocks[@]} - 1 ))
  for i in "${!chains_blocks[@]}"; do
    chains_json+="${chains_blocks[$i]}"
    (( i < last_c )) && chains_json+=","
    chains_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
$chains_json
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: TCP Direct MultiOut gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}TCP Direct MultiOut gost-IN configured.${RESET}"
  pause
}
tcp_direct_multiout_out() { tcp_direct_oneone_out; }

tcp_direct_lb_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}TCP Direct Loadbalancer (gost-IN)${RESET}\n"

  local out_count forwards
  read -rp "How much OUT? " out_count
  read -rp "Forward ports: " forwards
  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 ]] && {
    add_notice "${BOLD}${RED}Invalid OUT count.${RESET}"; pause; return 0; }
  [[ -z "$forwards" ]] && { add_notice "${BOLD}${RED}Missing forward ports.${RESET}"; pause; return 0; }

  local -a ports
  mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local -a node_blocks=()
  local i out_ip tunnel_port user pass

  for ((i=1; i<=out_count; i++)); do
    echo -e "${BOLD}${YELLOW}\n--- OUT $i ---${RESET}"
    read -rp "Gost Out $i IP: " out_ip
    read -rp "Gost Out $i Tunnel Port: " tunnel_port
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass
    [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    node_blocks+=("$(cat <<EOF
            {
              "name": "to-gost$i",
              "addr": "$out_ip:$tunnel_port",
              "connector": { "type": "relay", "auth": { "username": "$user", "password": "$pass" } },
              "dialer": { "type": "tcp" }
            }
EOF
)")
  done

  local nodes_json="" last_n=$(( ${#node_blocks[@]} - 1 ))
  for i in "${!node_blocks[@]}"; do
    nodes_json+="${node_blocks[$i]}"
    (( i < last_n )) && nodes_json+=","
    nodes_json+=$'\n'
  done

  local -a service_blocks=()
  local p
  for p in "${ports[@]}"; do
    service_blocks+=("$(cat <<EOF
    {
      "name": "public-$p",
      "addr": ":$p",
      "handler": { "type": "tcp", "chain": "to-backends" },
      "listener": { "type": "tcp" },
      "forwarder": { "nodes": [ { "name": "gost-x-$p", "addr": "127.0.0.1:$p" } ] }
    }
EOF
)")
  done

  local services_json="" last_s=$(( ${#service_blocks[@]} - 1 ))
  for i in "${!service_blocks[@]}"; do
    services_json+="${service_blocks[$i]}"
    (( i < last_s )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
    {
      "name": "to-backends",
      "selector": { "strategy": "round", "maxFails": 1, "failTimeout": "10s" },
      "hops": [
        { "name": "hop-0", "nodes": [
$nodes_json
        ] }
      ]
    }
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: TCP Direct Loadbalancer gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}TCP Direct Loadbalancer gost-IN configured.${RESET}"
  pause
}
tcp_direct_lb_out() { tcp_direct_oneone_out; }

tcp_reverse_oneone_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}TCP Reverse OneOne (gost-IN)${RESET}\n"

  local out_ip tunnel_port user pass
  read -rp "Gost-OUT IP address: " out_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass

  [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
    {
      "name": "relay-tcp-bind-$tunnel_port",
      "addr": ":$tunnel_port",
      "admission": "only-b",
      "handler": { "type": "relay", "auther": "backend-auth", "metadata": { "bind": true } },
      "listener": { "type": "tcp" }
    }
  ],
  "admissions": [
    { "name": "only-b", "whitelist": true, "matchers": [ "$out_ip" ] }
  ],
  "authers": [
    { "name": "backend-auth", "auths": [ { "username": "$user", "password": "$pass" } ] }
  ],
  "log": { "level": "error", "format": "text", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: TCP Reverse OneOne gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}TCP Reverse OneOne gost-IN configured.${RESET}"
  pause
}

tcp_reverse_oneone_out() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}TCP Reverse OneOne (gost-OUT)${RESET}\n"

  local in_ip tunnel_port user pass forwards
  read -rp "gost-IN IP address: " in_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "Forwards Port(s): " forwards

  [[ -z "$in_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports
  mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local -a blocks=()
  local p
  for p in "${ports[@]}"; do
    blocks+=("$(cat <<EOF
    {
      "name": "rtcp-$p",
      "addr": ":$p",
      "handler": { "type": "rtcp" },
      "listener": { "type": "rtcp", "chain": "to-a" },
      "forwarder": { "nodes": [ { "name": "gost-x-$p", "addr": "127.0.0.1:$p" } ] }
    }
EOF
)")
  done

  local services_json="" last_b=$(( ${#blocks[@]} - 1 ))
  local i
  for i in "${!blocks[@]}"; do
    services_json+="${blocks[$i]}"
    (( i < last_b )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-out"
  local config_path="$config_dir/gost-out.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
    {
      "name": "to-a",
      "hops": [
        { "name": "hop-0", "nodes": [
          {
            "name": "relay-client-x",
            "addr": "$in_ip:$tunnel_port",
            "connector": { "type": "relay", "auth": { "username": "$user", "password": "$pass" } },
            "dialer": { "type": "tcp" }
          }
        ] }
      ]
    }
  ],
  "log": { "level": "error", "format": "text", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-out.service"
  install_service_unit "gost-out.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: TCP Reverse OneOne gost-OUT configured.${RESET}"
  add_notice "${BOLD}${GREEN}TCP Reverse OneOne gost-OUT configured.${RESET}"
  pause
}

tcp_reverse_multiout_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}TCP Reverse MultiOut (gost-IN)${RESET}\n"

  local out_count tunnel_port
  read -rp "How much gost-OUT? " out_count
  read -rp "Tunnel Port: " tunnel_port

  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 || -z "$tunnel_port" ]] && {
    add_notice "${BOLD}${RED}Invalid inputs.${RESET}"; pause; return 0; }

  local -a matchers=()
  local -a auths=()

  local i ip user pass
  for ((i=1; i<=out_count; i++)); do
    echo -e "${BOLD}${YELLOW}\n--- OUT $i ---${RESET}"
    read -rp "Gost Out $i IP address: " ip
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass

    [[ -z "$ip" || -z "$user" || -z "$pass" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    matchers+=("        \"$ip\"")
    auths+=("        { \"username\": \"$user\", \"password\": \"$pass\" }")
  done

  local matchers_json="" auths_json=""
  local last_m=$(( ${#matchers[@]} - 1 ))
  local last_a=$(( ${#auths[@]} - 1 ))

  for i in "${!matchers[@]}"; do
    matchers_json+="${matchers[$i]}"
    (( i < last_m )) && matchers_json+=","
    matchers_json+=$'\n'
  done

  for i in "${!auths[@]}"; do
    auths_json+="${auths[$i]}"
    (( i < last_a )) && auths_json+=","
    auths_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
    {
      "name": "relay-tcp-bind-$tunnel_port",
      "addr": ":$tunnel_port",
      "admission": "only-outs",
      "handler": { "type": "relay", "auther": "backends-auth", "metadata": { "bind": true } },
      "listener": { "type": "tcp" }
    }
  ],
  "admissions": [
    { "name": "only-outs", "whitelist": true, "matchers": [
$matchers_json
    ] }
  ],
  "authers": [
    { "name": "backends-auth", "auths": [
$auths_json
    ] }
  ],
  "log": { "level": "error", "format": "text", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: TCP Reverse MultiOut gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}TCP Reverse MultiOut gost-IN configured.${RESET}"
  pause
}
tcp_reverse_multiout_out() { tcp_reverse_oneone_out; }

tcp_reverse_lb_in() { ws_reverse_lb_in; }
tcp_reverse_lb_out() { tcp_reverse_oneone_out; }


icmp_direct_oneone_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}ICMP Direct OneOne (gost-IN)${RESET}\n"

  local out_ip user pass forwards ttl
  read -rp "OUT server IP address: " out_ip
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "TTL seconds (5-120): " ttl
  read -rp "Forwards Port(s): " forwards

  [[ -z "$ttl" || ! "$ttl" =~ ^[0-9]+$ || "$ttl" -lt 5 || "$ttl" -gt 120 ]] && ttl=10
  [[ -z "$out_ip" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports
  mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && {
    add_notice "${BOLD}${RED}No valid forward ports.${RESET}"; pause; return 0; }

  local services_json=""
  local i p last_index=$(( ${#ports[@]} - 1 ))
  for i in "${!ports[@]}"; do
    p="${ports[$i]}"
    services_json+=$(cat <<EOF
    { "name": "public-$p", "addr": ":$p",
      "handler": { "type": "tcp", "chain": "to-b-icmp" },
      "listener": { "type": "tcp" },
      "forwarder": { "nodes": [ { "name": "gost-x-$p", "addr": "127.0.0.1:$p" } ] } }
EOF
)
    (( i < last_index )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
    {
      "name": "to-b-icmp",
      "hops": [
        { "name": "hop-0", "nodes": [
          {
            "name": "relay-b-icmp",
            "addr": "$out_ip:0",
            "connector": {
              "type": "relay",
              "auth": { "username": "$user", "password": "$pass" }
            },
            "dialer": {
              "type": "icmp",
              "metadata": { "keepAlive": true, "ttl": "${ttl}s" }
            }
          }
        ] }
      ]
    }
  ],
  "log": { "level": "error", "format": "text", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: ICMP Direct OneOne gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}ICMP Direct OneOne gost-IN configured.${RESET}"
  pause
}

icmp_direct_oneone_out() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}ICMP Direct OneOne (gost-OUT)${RESET}\n"

  local in_ip user pass ttl
  read -rp "gost-IN IP address: " in_ip
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "TTL seconds (5-120): " ttl

  [[ -z "$ttl" || ! "$ttl" =~ ^[0-9]+$ || "$ttl" -lt 5 || "$ttl" -gt 120 ]] && ttl=10
  [[ -z "$in_ip" || -z "$user" || -z "$pass" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local config_dir="/etc/gost-out"
  local config_path="$config_dir/gost-out.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
    {
      "name": "relay-icmp-bind",
      "addr": ":0",
      "admission": "only-a",
      "handler": {
        "type": "relay",
        "auther": "backends-auth",
        "metadata": { "bind": true }
      },
      "listener": {
        "type": "icmp",
        "metadata": { "keepAlive": true, "ttl": "${ttl}s", "backlog": 8192 }
      }
    }
  ],
  "admissions": [
    { "name": "only-a", "whitelist": true, "matchers": [ "$in_ip" ] }
  ],
  "authers": [
    { "name": "backends-auth", "auths": [ { "username": "$user", "password": "$pass" } ] }
  ],
  "log": { "level": "error", "format": "text", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-out.service"
  install_service_unit "gost-out.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: ICMP Direct OneOne gost-OUT configured.${RESET}"
  add_notice "${BOLD}${GREEN}ICMP Direct OneOne gost-OUT configured.${RESET}"
  pause
}

icmp_direct_multiout_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}ICMP Direct MultiOut (gost-IN)${RESET}\n"

  local out_count
  read -rp "How much OUT? " out_count
  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 ]] && {
    add_notice "${BOLD}${RED}Invalid OUT count.${RESET}"; pause; return 0; }

  local -a chains_blocks=()
  local -a service_blocks=()

  local i out_ip user pass forwards ttl
  for ((i=1; i<=out_count; i++)); do
    echo -e "${BOLD}${YELLOW}\n--- OUT $i ---${RESET}"
    read -rp "Gost Out $i IP: " out_ip
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass
    read -rp "TTL seconds (5-120) for Out $i: " ttl
    read -rp "Forwards Port(s) for Out $i: " forwards

    [[ -z "$ttl" || ! "$ttl" =~ ^[0-9]+$ || "$ttl" -lt 5 || "$ttl" -gt 120 ]] && ttl=10
    [[ -z "$out_ip" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    local chain_name="to-gost${i}-icmp"
    chains_blocks+=("$(cat <<EOF
    {
      "name": "$chain_name",
      "hops": [
        { "name": "hop-$i", "nodes": [
          {
            "name": "relay-gost$i-icmp",
            "addr": "$out_ip:0",
            "connector": {
              "type": "relay",
              "auth": { "username": "$user", "password": "$pass" }
            },
            "dialer": {
              "type": "icmp",
              "metadata": { "keepAlive": true, "ttl": "${ttl}s" }
            }
          }
        ] }
      ]
    }
EOF
)")

    local -a ports=()
    mapfile -t ports < <(parse_ports "$forwards")
    ((${#ports[@]}==0)) && {
      add_notice "${BOLD}${RED}No valid ports for Out $i.${RESET}"; pause; return 0; }

    local p
    for p in "${ports[@]}"; do
      service_blocks+=("$(cat <<EOF
    { "name": "public-$p-to-gost$i", "addr": ":$p",
      "handler": { "type": "tcp", "chain": "$chain_name" },
      "listener": { "type": "tcp" },
      "forwarder": { "nodes": [ { "name": "gost-$i-$p", "addr": "127.0.0.1:$p" } ] } }
EOF
)")
    done
  done

  local services_json="" last_s=$(( ${#service_blocks[@]} - 1 ))
  for i in "${!service_blocks[@]}"; do
    services_json+="${service_blocks[$i]}"
    (( i < last_s )) && services_json+=","
    services_json+=$'\n'
  done

  local chains_json="" last_c=$(( ${#chains_blocks[@]} - 1 ))
  for i in "${!chains_blocks[@]}"; do
    chains_json+="${chains_blocks[$i]}"
    (( i < last_c )) && chains_json+=","
    chains_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
$chains_json
  ],
  "log": { "level": "error", "format": "text", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: ICMP Direct MultiOut gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}ICMP Direct MultiOut gost-IN configured.${RESET}"
  pause
}

icmp_direct_multiout_out() { icmp_direct_oneone_out; }


icmp_reverse_oneone_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}ICMP Reverse OneOne (gost-IN)${RESET}\n"

  local out_ip user pass ttl
  read -rp "Gost-OUT IP address: " out_ip
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "TTL seconds (5-120): " ttl

  [[ -z "$ttl" || ! "$ttl" =~ ^[0-9]+$ || "$ttl" -lt 5 || "$ttl" -gt 120 ]] && ttl=10
  [[ -z "$out_ip" || -z "$user" || -z "$pass" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
    {
      "name": "relay-icmp-bind",
      "addr": ":0",
      "admission": "only-b",
      "handler": {
        "type": "relay",
        "auther": "backends-auth",
        "metadata": { "bind": true }
      },
      "listener": {
        "type": "icmp",
        "metadata": { "keepAlive": true, "ttl": "${ttl}s", "backlog": 8192 }
      }
    }
  ],
  "admissions": [
    { "name": "only-b", "whitelist": true, "matchers": [ "$out_ip" ] }
  ],
  "authers": [
    { "name": "backends-auth", "auths": [ { "username": "$user", "password": "$pass" } ] }
  ],
  "log": { "level": "error", "format": "text", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: ICMP Reverse OneOne gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}ICMP Reverse OneOne gost-IN configured.${RESET}"
  pause
}

icmp_reverse_oneone_out() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}ICMP Reverse OneOne (gost-OUT)${RESET}\n"

  local in_ip tunnel_port user pass ttl forwards
  read -rp "gost-IN IP address: " in_ip
  read -rp "Tunnel Port (default 443): " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "TTL seconds (5-120): " ttl
  read -rp "Forwards Port(s): " forwards

  [[ -z "$tunnel_port" ]] && tunnel_port=443
  [[ -z "$ttl" || ! "$ttl" =~ ^[0-9]+$ || "$ttl" -lt 5 || "$ttl" -gt 120 ]] && ttl=10
  [[ -z "$in_ip" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports
  mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && {
    add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local -a blocks=()
  local p
  for p in "${ports[@]}"; do
    blocks+=("$(cat <<EOF
    { "name": "rtcp-$p", "addr": ":$p", "handler": { "type": "rtcp" },
      "listener": { "type": "rtcp", "chain": "to-a" },
      "forwarder": { "nodes": [ { "name": "gost-x-$p", "addr": "127.0.0.1:$p" } ] } }
EOF
)")
  done

  local services_json="" last_b=$(( ${#blocks[@]} - 1 ))
  local i
  for i in "${!blocks[@]}"; do
    services_json+="${blocks[$i]}"
    (( i < last_b )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-out"
  local config_path="$config_dir/gost-out.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
    {
      "name": "to-a",
      "hops": [
        { "name": "hop-0", "nodes": [
          {
            "name": "relay-icmp-client",
            "addr": "$in_ip:$tunnel_port",
            "connector": {
              "type": "relay",
              "auth": { "username": "$user", "password": "$pass" }
            },
            "dialer": {
              "type": "icmp",
              "metadata": { "keepAlive": true, "ttl": "${ttl}s" }
            }
          }
        ] }
      ]
    }
  ],
  "log": { "level": "error", "format": "text", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-out.service"
  install_service_unit "gost-out.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: ICMP Reverse OneOne gost-OUT configured.${RESET}"
  add_notice "${BOLD}${GREEN}ICMP Reverse OneOne gost-OUT configured.${RESET}"
  pause
}


icmp_reverse_multiout_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}ICMP Reverse MultiOut (gost-IN)${RESET}\n"

  local out_count ttl
  read -rp "How much gost-OUT? " out_count
  read -rp "TTL seconds (5-120): " ttl

  [[ -z "$ttl" || ! "$ttl" =~ ^[0-9]+$ || "$ttl" -lt 5 || "$ttl" -gt 120 ]] && ttl=10
  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 ]] && {
    add_notice "${BOLD}${RED}Invalid inputs.${RESET}"; pause; return 0; }

  local -a matchers=()
  local -a auths=()

  local i ip user pass
  for ((i=1; i<=out_count; i++)); do
    echo -e "${BOLD}${YELLOW}\n--- OUT $i ---${RESET}"
    read -rp "Gost Out $i IP address: " ip
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass

    [[ -z "$ip" || -z "$user" || -z "$pass" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    matchers+=("$ip")
    auths+=("{ \"username\": \"$user\", \"password\": \"$pass\" }")
  done

  local matchers_json="" auths_json=""
  local last_m=$(( ${#matchers[@]} - 1 ))
  local last_a=$(( ${#auths[@]} - 1 ))

  for i in "${!matchers[@]}"; do
    matchers_json+="        \"${matchers[$i]}\""
    (( i < last_m )) && matchers_json+=","
    matchers_json+=$'\n'
  done

  for i in "${!auths[@]}"; do
    auths_json+="        ${auths[$i]}"
    (( i < last_a )) && auths_json+=","
    auths_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
    {
      "name": "relay-icmp-bind-443",
      "addr": ":0",
      "admission": "only-outs",
      "handler": {
        "type": "relay",
        "auther": "backends-auth",
        "metadata": { "bind": true }
      },
      "listener": {
        "type": "icmp",
        "metadata": { "keepAlive": true, "ttl": "${ttl}s", "backlog": 8192 }
      }
    }
  ],
  "admissions": [
    {
      "name": "only-outs",
      "whitelist": true,
      "matchers": [
$matchers_json
      ]
    }
  ],
  "authers": [
    {
      "name": "backends-auth",
      "auths": [
$auths_json
      ]
    }
  ],
  "log": { "level": "error", "format": "text", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: ICMP Reverse MultiOut gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}ICMP Reverse MultiOut gost-IN configured.${RESET}"
  pause
}

icmp_reverse_multiout_out() { icmp_reverse_oneone_out; }



quic_tcp_direct_oneone_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}QUIC(TCP Forward) Direct OneOne (gost-IN)${RESET}\n"

  local out_ip tunnel_port user pass forwards
  read -rp "OUT server IP address: " out_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "Forwards Port(s): " forwards
  [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports
  mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local services_json=""
  local i p last_index=$(( ${#ports[@]} - 1 ))
  for i in "${!ports[@]}"; do
    p="${ports[$i]}"
    services_json+=$(cat <<EOF
    { "name": "public-$p", "addr": ":$p",
      "handler": { "type": "tcp", "chain": "to-B" }, "listener": { "type": "tcp" },
      "forwarder": { "nodes": [ { "name": "b-$p", "addr": "$out_ip:$p" } ] } }
EOF
)
    (( i < last_index )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-in"; local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
    {
      "name": "to-B",
      "hops": [
        { "name": "hop-b", "nodes": [
          {
            "name": "relay-b-quic",
            "addr": "$out_ip:$tunnel_port",
            "connector": { "type": "relay", "auth": { "username": "$user", "password": "$pass" } },
            "dialer": { "type": "quic", "metadata": { "keepAlive": true } }
          }
        ] }
      ]
    }
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: QUIC TCP Direct OneOne gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}QUIC TCP Direct OneOne gost-IN configured.${RESET}"
  pause
}

quic_tcp_direct_oneone_out() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}QUIC(TCP Forward) Direct OneOne (gost-OUT)${RESET}\n"

  local in_ip tunnel_port user pass
  read -rp "gost-IN IP address: " in_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass
  [[ -z "$in_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local config_dir="/etc/gost-out"; local config_path="$config_dir/gost-out.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
    { "name": "relay-quic-$tunnel_port", "addr": ":$tunnel_port", "admission": "only-a",
      "handler": { "type": "relay", "auther": "relay-auth" }, "listener": { "type": "quic" } }
  ],
  "admissions": [
    { "name": "only-a", "whitelist": true, "matchers": [ "127.0.0.1", "::1", "$in_ip" ] }
  ],
  "authers": [
    { "name": "relay-auth", "auths": [ { "username": "$user", "password": "$pass" } ] }
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-out.service"
  install_service_unit "gost-out.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: QUIC TCP Direct OneOne gost-OUT configured.${RESET}"
  add_notice "${BOLD}${GREEN}QUIC TCP Direct OneOne gost-OUT configured.${RESET}"
  pause
}

quic_tcp_direct_multiout_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}QUIC(TCP Forward) Direct MultiOut (gost-IN)${RESET}\n"

  local out_count
  read -rp "How much OUT? " out_count
  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 ]] && {
    add_notice "${BOLD}${RED}Invalid OUT count.${RESET}"; pause; return 0; }

  local -a chains_blocks=()
  local -a service_blocks=()

  local i out_ip tunnel_port user pass forwards
  for ((i=1; i<=out_count; i++)); do
    echo -e "${BOLD}${YELLOW}\n--- OUT $i ---${RESET}"
    read -rp "Gost Out $i IP: " out_ip
    read -rp "Gost Out $i Tunnel Port: " tunnel_port
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass
    read -rp "Forwards Port(s) for Out $i: " forwards

    [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    local chain_name="to-gost${i}-quic"
    chains_blocks+=("$(cat <<EOF
    {
      "name": "$chain_name",
      "hops": [
        { "name": "hop-$i", "nodes": [
          {
            "name": "relay-gost$i-quic",
            "addr": "$out_ip:$tunnel_port",
            "connector": { "type": "relay", "auth": { "username": "$user", "password": "$pass" } },
            "dialer": { "type": "quic", "metadata": { "keepAlive": true } }
          }
        ] }
      ]
    }
EOF
)")

    local -a ports=()
    mapfile -t ports < <(parse_ports "$forwards")
    ((${#ports[@]}==0)) && {
      add_notice "${BOLD}${RED}No valid ports for Out $i.${RESET}"; pause; return 0; }

    local p
    for p in "${ports[@]}"; do
      service_blocks+=("$(cat <<EOF
    { "name": "public-$p-to-gost$i", "addr": ":$p",
      "handler": { "type": "tcp", "chain": "$chain_name" }, "listener": { "type": "tcp" },
      "forwarder": { "nodes": [ { "name": "gost-$i-$p", "addr": "$out_ip:$p" } ] } }
EOF
)")
    done
  done

  local services_json="" last_s=$(( ${#service_blocks[@]} - 1 ))
  for i in "${!service_blocks[@]}"; do
    services_json+="${service_blocks[$i]}"
    (( i < last_s )) && services_json+=","
    services_json+=$'\n'
  done

  local chains_json="" last_c=$(( ${#chains_blocks[@]} - 1 ))
  for i in "${!chains_blocks[@]}"; do
    chains_json+="${chains_blocks[$i]}"
    (( i < last_c )) && chains_json+=","
    chains_json+=$'\n'
  done

  local config_dir="/etc/gost-in"; local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
$chains_json
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: QUIC TCP Direct MultiOut gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}QUIC TCP Direct MultiOut gost-IN configured.${RESET}"
  pause
}
quic_tcp_direct_multiout_out() { quic_tcp_direct_oneone_out; }


quic_tcp_reverse_oneone_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}QUIC(TCP Forward) Reverse OneOne (gost-IN)${RESET}\n"

  local out_ip tunnel_port user pass
  read -rp "Gost-OUT IP address: " out_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass
  [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local config_dir="/etc/gost-in"; local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
    { "name": "relay-quic-bind-$tunnel_port", "addr": ":$tunnel_port", "admission": "only-b",
      "handler": { "type": "relay", "auther": "relay-auth", "metadata": { "bind": true } },
      "listener": { "type": "quic" } }
  ],
  "admissions": [
    { "name": "only-b", "whitelist": true, "matchers": [ "$out_ip", "127.0.0.1", "::1" ] }
  ],
  "authers": [
    { "name": "relay-auth", "auths": [ { "username": "$user", "password": "$pass" } ] }
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: QUIC TCP Reverse OneOne gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}QUIC TCP Reverse OneOne gost-IN configured.${RESET}"
  pause
}

quic_tcp_reverse_oneone_out() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}QUIC(TCP Forward) Reverse OneOne (gost-OUT)${RESET}\n"

  local in_ip tunnel_port user pass forwards
  read -rp "gost-IN IP address: " in_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "Forwards Port(s): " forwards
  [[ -z "$in_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports
  mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && { add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local -a blocks=()
  local p
  for p in "${ports[@]}"; do
    blocks+=("$(cat <<EOF
    { "name": "rtcp-$p", "addr": ":$p", "handler": { "type": "rtcp" },
      "listener": { "type": "rtcp", "chain": "to-a" },
      "forwarder": { "nodes": [ { "name": "local-$p", "addr": "127.0.0.1:$p" } ] } }
EOF
)")
  done

  local services_json="" last_b=$(( ${#blocks[@]} - 1 ))
  local i
  for i in "${!blocks[@]}"; do
    services_json+="${blocks[$i]}"
    (( i < last_b )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-out"; local config_path="$config_dir/gost-out.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
    {
      "name": "to-a",
      "hops": [
        { "name": "hop-a", "nodes": [
          {
            "name": "relay-a-quic",
            "addr": "$in_ip:$tunnel_port",
            "connector": { "type": "relay", "auth": { "username": "$user", "password": "$pass" } },
            "dialer": { "type": "quic" }
          }
        ] }
      ]
    }
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-out.service"
  install_service_unit "gost-out.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: QUIC TCP Reverse OneOne gost-OUT configured.${RESET}"
  add_notice "${BOLD}${GREEN}QUIC TCP Reverse OneOne gost-OUT configured.${RESET}"
  pause
}



quic_tcp_reverse_multiout_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}QUIC(TCP Forward) Reverse MultiOut (gost-IN)${RESET}\n"

  local out_count tunnel_port
  read -rp "How much gost-OUT? " out_count
  read -rp "Tunnel Port: " tunnel_port

  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 || -z "$tunnel_port" ]] && {
    add_notice "${BOLD}${RED}Invalid inputs.${RESET}"; pause; return 0; }

  local -a matchers=()
  local -a auths=()

  local i ip user pass
  for ((i=1; i<=out_count; i++)); do
    echo -e "${BOLD}${YELLOW}\n--- OUT $i ---${RESET}"
    read -rp "Gost Out $i IP address: " ip
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass

    [[ -z "$ip" || -z "$user" || -z "$pass" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    matchers+=("$ip")
    auths+=("{ \"username\": \"$user\", \"password\": \"$pass\" }")
  done

  matchers+=("127.0.0.1" "::1")

  local matchers_json="" last_m=$(( ${#matchers[@]} - 1 ))
  for i in "${!matchers[@]}"; do
    matchers_json+="        \"${matchers[$i]}\""
    (( i < last_m )) && matchers_json+=","
    matchers_json+=$'\n'
  done

  local auths_json="" last_a=$(( ${#auths[@]} - 1 ))
  for i in "${!auths[@]}"; do
    auths_json+="        ${auths[$i]}"
    (( i < last_a )) && auths_json+=","
    auths_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"

  write_atomic "$config_path" <<EOF
{
  "services": [
    {
      "name": "relay-quic-bind-$tunnel_port",
      "addr": ":$tunnel_port",
      "admission": "only-bc",
      "handler": {
        "type": "relay",
        "auther": "backends-auth",
        "metadata": { "bind": true }
      },
      "listener": { "type": "quic" }
    }
  ],

  "admissions": [
    {
      "name": "only-bc",
      "whitelist": true,
      "matchers": [
$matchers_json      ]
    }
  ],

  "authers": [
    {
      "name": "backends-auth",
      "auths": [
$auths_json      ]
    }
  ],

  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: QUIC TCP Reverse MultiOut gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}QUIC TCP Reverse MultiOut gost-IN configured.${RESET}"
  pause
}

quic_tcp_reverse_multiout_out() { quic_tcp_reverse_oneone_out; }



quic_udp_direct_oneone_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}QUIC(UDP Forward) Direct OneOne (gost-IN)${RESET}\n"

  local out_ip tunnel_port user pass forwards
  read -rp "OUT server IP address: " out_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "UDP Forward Ports(s): " forwards

  [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports
  mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && {
    add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }


  local services_json=""
  local i p last_index=$(( ${#ports[@]} - 1 ))
  for i in "${!ports[@]}"; do
    p="${ports[$i]}"
    services_json+=$(cat <<EOF
    { "name": "public-$p", "addr": ":$p",
      "handler": { "type": "udp", "chain": "to-B" },
      "listener": { "type": "udp" },
      "forwarder": { "nodes": [ { "name": "b-$p", "addr": "$out_ip:$p" } ] } }
EOF
)
    (( i < last_index )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
    {
      "name": "to-B",
      "hops": [
        { "name": "hop-b", "nodes": [
          {
            "name": "relay-B-quic",
            "addr": "$out_ip:$tunnel_port",
            "connector": { "type": "relay",
              "auth": { "username": "$user", "password": "$pass" } },
            "dialer": { "type": "quic" }
          }
        ] }
      ]
    }
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: QUIC UDP Direct OneOne gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}QUIC UDP Direct OneOne gost-IN configured.${RESET}"
  pause
}

quic_udp_direct_oneone_out() { quic_tcp_direct_oneone_out; }


quic_udp_direct_multiout_in() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}QUIC(UDP Forward) Direct MultiOut (gost-IN)${RESET}\n"

  local out_count
  read -rp "How much OUT? " out_count
  [[ -z "$out_count" || ! "$out_count" =~ ^[0-9]+$ || "$out_count" -lt 1 ]] && {
    add_notice "${BOLD}${RED}Invalid OUT count.${RESET}"; pause; return 0; }

  local -a chains_blocks=()
  local -a service_blocks=()

  local i out_ip tunnel_port user pass forwards
  for ((i=1; i<=out_count; i++)); do
    echo -e "${BOLD}${YELLOW}\n--- OUT $i ---${RESET}"
    read -rp "Gost Out $i IP: " out_ip
    read -rp "Gost Out $i Tunnel Port: " tunnel_port
    read -rp "Gost Out $i Username: " user
    read -rp "Gost Out $i Password: " pass
    read -rp "UDP Forward Ports(s) for Out $i: " forwards

    [[ -z "$out_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
      add_notice "${BOLD}${RED}Missing inputs for Out $i.${RESET}"; pause; return 0; }

    local chain_name="to-gost${i}-quic-udp"
    chains_blocks+=("$(cat <<EOF
    {
      "name": "$chain_name",
      "hops": [
        { "name": "hop-$i", "nodes": [
          {
            "name": "relay-gost$i-quic",
            "addr": "$out_ip:$tunnel_port",
            "connector": { "type": "relay",
              "auth": { "username": "$user", "password": "$pass" } },
            "dialer": { "type": "quic", "metadata": { "keepAlive": true } }
          }
        ] }
      ]
    }
EOF
)")

    local -a ports=()
    mapfile -t ports < <(parse_ports "$forwards")
    ((${#ports[@]}==0)) && {
      add_notice "${BOLD}${RED}No valid ports for Out $i.${RESET}"; pause; return 0; }

    local p
    for p in "${ports[@]}"; do
      service_blocks+=("$(cat <<EOF
    { "name": "udp-$p-to-gost$i", "addr": ":$p",
      "handler": { "type": "udp", "chain": "$chain_name" },
      "listener": { "type": "udp" },
      "forwarder": {
        "nodes": [ { "name": "gost-$i-$p", "addr": "$out_ip:$p" } ]
      } }
EOF
)")
    done
  done

  local services_json="" last_s=$(( ${#service_blocks[@]} - 1 ))
  for i in "${!service_blocks[@]}"; do
    services_json+="${service_blocks[$i]}"
    (( i < last_s )) && services_json+=","
    services_json+=$'\n'
  done

  local chains_json="" last_c=$(( ${#chains_blocks[@]} - 1 ))
  for i in "${!chains_blocks[@]}"; do
    chains_json+="${chains_blocks[$i]}"
    (( i < last_c )) && chains_json+=","
    chains_json+=$'\n'
  done

  local config_dir="/etc/gost-in"
  local config_path="$config_dir/gost-in.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
$chains_json
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-in.service"
  install_service_unit "gost-in.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: QUIC UDP Direct MultiOut gost-IN configured.${RESET}"
  add_notice "${BOLD}${GREEN}QUIC UDP Direct MultiOut gost-IN configured.${RESET}"
  pause
}

quic_udp_direct_multiout_out() { quic_udp_direct_oneone_out; }


quic_udp_reverse_oneone_in() { 
  quic_tcp_reverse_oneone_in
}

quic_udp_reverse_oneone_out() {
  need_root || return 0
  clear_screen; render_banner; render_notices; echo; render_status_block
  echo -e "${BOLD}${CYAN}QUIC(UDP Forward) Reverse OneOne (gost-OUT)${RESET}\n"

  local in_ip tunnel_port user pass forwards
  read -rp "gost-IN IP address: " in_ip
  read -rp "Tunnel Port: " tunnel_port
  read -rp "Username: " user
  read -rp "Password: " pass
  read -rp "UDP Forward Ports(s): " forwards

  [[ -z "$in_ip" || -z "$tunnel_port" || -z "$user" || -z "$pass" || -z "$forwards" ]] && {
    add_notice "${BOLD}${RED}Missing inputs.${RESET}"; pause; return 0; }

  local -a ports
  mapfile -t ports < <(parse_ports "$forwards")
  ((${#ports[@]}==0)) && {
    add_notice "${BOLD}${RED}No valid ports.${RESET}"; pause; return 0; }

  local -a blocks=()
  local p
  for p in "${ports[@]}"; do
    blocks+=("$(cat <<EOF
    { "name": "rudp-$p", "addr": ":$p", "handler": { "type": "rudp" },
      "listener": { "type": "rudp", "chain": "to-a" },
      "forwarder": {
        "nodes": [ { "name": "local-$p", "addr": "127.0.0.1:$p" } ]
      } }
EOF
)")
  done

  local services_json="" last_b=$(( ${#blocks[@]} - 1 ))
  local i
  for i in "${!blocks[@]}"; do
    services_json+="${blocks[$i]}"
    (( i < last_b )) && services_json+=","
    services_json+=$'\n'
  done

  local config_dir="/etc/gost-out"
  local config_path="$config_dir/gost-out.json"
  ensure_dir "$config_dir"
  write_atomic "$config_path" <<EOF
{
  "services": [
$services_json
  ],
  "chains": [
    {
      "name": "to-a",
      "hops": [
        { "name": "hop-a", "nodes": [
          {
            "name": "relay-a-quic",
            "addr": "$in_ip:$tunnel_port",
            "connector": { "type": "relay",
              "auth": { "username": "$user", "password": "$pass" } },
            "dialer": { "type": "quic" }
          }
        ] }
      ]
    }
  ],
  "log": { "level": "error", "format": "json", "output": "stderr" }
}
EOF

  remove_service_if_exists "gost-out.service"
  install_service_unit "gost-out.service" "$config_path"
  echo -e "\n${BOLD}${GREEN}DONE: QUIC UDP Reverse OneOne gost-OUT configured.${RESET}"
  add_notice "${BOLD}${GREEN}QUIC UDP Reverse OneOne gost-OUT configured.${RESET}"
  pause
}

quic_udp_reverse_multiout_in() { quic_tcp_reverse_multiout_in; }
quic_udp_reverse_multiout_out() { quic_udp_reverse_oneone_out; }



render_service_table() {
  local svc="$1" label="$2"
  local exists=0
  service_exists "$svc" && exists=1

  if (( exists==1 )); then
    local st enabled
    st="$(service_state "$svc" || true)"
    enabled="$(systemctl is-enabled "$svc" 2>/dev/null || echo "disabled")"

    echo -e "${BOLD}${PURPLE}┌──────────────────────────────────────────────┐${RESET}"
    echo -e "${BOLD}${PURPLE}│ ${label} - Service Status${RESET}"
    echo -e "${BOLD}${PURPLE}├──────────────────────────────────────────────┤${RESET}"
    echo -e "${BOLD}${PURPLE}│ Status : ${RESET}${BOLD}${CYAN}${st^}${RESET}"
    echo -e "${BOLD}${PURPLE}│ Enabled: ${RESET}${BOLD}${CYAN}${enabled^}${RESET}"
    echo -e "${BOLD}${PURPLE}└──────────────────────────────────────────────┘${RESET}"
  fi
}

collect_existing_services() {
  EXISTING_SERVICES=()
  service_exists "gost-in.service" && EXISTING_SERVICES+=("gost-in.service")
  service_exists "gost-out.service" && EXISTING_SERVICES+=("gost-out.service")
}

restart_existing_services() {
  collect_existing_services
  if ((${#EXISTING_SERVICES[@]}==0)); then
    add_notice "${BOLD}${RED}No GOST services found to restart.${RESET}"
    pause; return 0
  fi
  local s
  for s in "${EXISTING_SERVICES[@]}"; do
    systemctl restart "$s" >/dev/null 2>&1
  done
  add_notice "${BOLD}${GREEN}Service(s) restarted.${RESET}"
}

stop_existing_services() {
  collect_existing_services
  if ((${#EXISTING_SERVICES[@]}==0)); then
    add_notice "${BOLD}${RED}No GOST services found to stop.${RESET}"
    pause; return 0
  fi
  local s
  for s in "${EXISTING_SERVICES[@]}"; do
    systemctl stop "$s" >/dev/null 2>&1
  done
  add_notice "${BOLD}${GREEN}Service(s) stopped.${RESET}"
}

start_existing_services() {
  collect_existing_services
  if ((${#EXISTING_SERVICES[@]}==0)); then
    add_notice "${BOLD}${RED}No GOST services found to start.${RESET}"
    pause; return 0
  fi
  local s
  for s in "${EXISTING_SERVICES[@]}"; do
    systemctl start "$s" >/dev/null 2>&1
  done
  add_notice "${BOLD}${GREEN}Service(s) started.${RESET}"
}

disable_existing_services() {
  collect_existing_services
  if ((${#EXISTING_SERVICES[@]}==0)); then
    add_notice "${BOLD}${RED}No GOST services found to disable.${RESET}"
    pause; return 0
  fi
  local s st
  for s in "${EXISTING_SERVICES[@]}"; do
    st="$(service_state "$s" || true)"
    if [[ "$st" == "active" ]]; then
      systemctl stop "$s" >/dev/null 2>&1
    fi
    systemctl disable "$s" >/dev/null 2>&1
  done
  add_notice "${BOLD}${GREEN}Service(s) disabled (stopped first if needed).${RESET}"
}

enable_existing_services() {
  collect_existing_services
  if ((${#EXISTING_SERVICES[@]}==0)); then
    add_notice "${BOLD}${RED}No GOST services found to enable.${RESET}"
    pause; return 0
  fi
  local s st
  for s in "${EXISTING_SERVICES[@]}"; do
    systemctl enable "$s" >/dev/null 2>&1
    st="$(service_state "$s" || true)"
    if [[ "$st" == "active" ]]; then
      systemctl restart "$s" >/dev/null 2>&1
    else
      systemctl start "$s" >/dev/null 2>&1
    fi
  done
  add_notice "${BOLD}${GREEN}Service(s) enabled and (re)started.${RESET}"
}

service_management_menu() {
  while true; do
    clear_screen; render_banner; render_notices; echo; render_status_block

    collect_existing_services

    echo -e "${BOLD}${CYAN}Service Management${RESET}\n"

    if ((${#EXISTING_SERVICES[@]}==0)); then
      echo -e "${BOLD}${RED}No GOST-IN or GOST-OUT services found.${RESET}\n"
    else
      service_exists "gost-in.service" && render_service_table "gost-in.service" "GOST IN"
      service_exists "gost-out.service" && render_service_table "gost-out.service" "GOST OUT"
      echo
    fi

    echo -e "${BOLD}1. Restart service(s)${RESET}"
    echo -e "${BOLD}2. Stop service(s)${RESET}"
    echo -e "${BOLD}3. Start service(s)${RESET}"
    echo -e "${BOLD}4. Disable service(s)${RESET}"
    echo -e "${BOLD}5. Enable service(s)${RESET}"
    echo -e "${BOLD}0. Back${RESET}"
    render_footer; echo

    local c
    c="$(read_choice "Select option: ")"
    case "$c" in
      1) restart_existing_services; pause ;;
      2) stop_existing_services; pause ;;
      3) start_existing_services; pause ;;
      4) disable_existing_services; pause ;;
      5) enable_existing_services; pause ;;
      0) return 0 ;;
      *) add_notice "${BOLD}${RED}Invalid choice in Service Management.${RESET}" ;;
    esac
  done
}


mode_menu() {
  local side="$1"
  local proto="$2"

  while true; do
    clear_screen; render_banner; render_notices; echo; render_status_block
    echo -e "${BOLD}Protocol: ${proto} | Side: gost-${side}${RESET}\n"
    echo -e "${BOLD}1. Direct${RESET}"
    echo -e "${BOLD}2. Reverse${RESET}"
    echo -e "${BOLD}0. Back${RESET}"
    render_footer; echo

    local c
    c="$(read_choice "Select mode: ")"
    case "$c" in
      1) topology_menu "$side" "$proto" "Direct" ;;
      2) topology_menu "$side" "$proto" "Reverse" ;;
      0) return 0 ;;
      *) add_notice "${BOLD}${RED}Invalid choice in Mode Menu.${RESET}" ;;
    esac
  done
}

topology_menu() {
  local side="$1"
  local proto="$2"
  local mode="$3"

  local has_lb=0
  [[ "$proto" == "WebSocket(ws) for TCP forward" || "$proto" == "TCP for TCP forward" ]] && has_lb=1

  while true; do
    clear_screen; render_banner; render_notices; echo; render_status_block
    echo -e "${BOLD}Protocol: ${proto} | Mode: ${mode} | Side: gost-${side}${RESET}\n"
    echo -e "${BOLD}1. One in - One Out${RESET}"
    echo -e "${BOLD}2. One in - Multi Out${RESET}"
    if ((has_lb==1)); then echo -e "${BOLD}3. Loadbalancer${RESET}"; fi
    echo -e "${BOLD}0. Back${RESET}"
    render_footer; echo

    local c
    c="$(read_choice "Select topology: ")"

    case "$c" in
      1)
        if [[ "$proto" == "WebSocket(ws) for TCP forward" && "$mode" == "Direct" ]]; then
          [[ "$side" == "IN" ]] && ws_direct_oneone_in || ws_direct_oneone_out
        elif [[ "$proto" == "WebSocket(ws) for TCP forward" && "$mode" == "Reverse" ]]; then
          [[ "$side" == "IN" ]] && ws_reverse_oneone_in || ws_reverse_oneone_out

        elif [[ "$proto" == "TCP for TCP forward" && "$mode" == "Direct" ]]; then
          [[ "$side" == "IN" ]] && tcp_direct_oneone_in || tcp_direct_oneone_out
        elif [[ "$proto" == "TCP for TCP forward" && "$mode" == "Reverse" ]]; then
          [[ "$side" == "IN" ]] && tcp_reverse_oneone_in || tcp_reverse_oneone_out

        elif [[ "$proto" == "QUIC for TCP forward" && "$mode" == "Direct" ]]; then
          [[ "$side" == "IN" ]] && quic_tcp_direct_oneone_in || quic_tcp_direct_oneone_out
        elif [[ "$proto" == "QUIC for TCP forward" && "$mode" == "Reverse" ]]; then
          [[ "$side" == "IN" ]] && quic_tcp_reverse_oneone_in || quic_tcp_reverse_oneone_out

        elif [[ "$proto" == "QUIC for UDP forward" && "$mode" == "Direct" ]]; then
          [[ "$side" == "IN" ]] && quic_udp_direct_oneone_in || quic_udp_direct_oneone_out
        elif [[ "$proto" == "QUIC for UDP forward" && "$mode" == "Reverse" ]]; then
          [[ "$side" == "IN" ]] && quic_udp_reverse_oneone_in || quic_udp_reverse_oneone_out

        elif [[ "$proto" == "ICMP for TCP forward" && "$mode" == "Direct" ]]; then
          [[ "$side" == "IN" ]] && icmp_direct_oneone_in || icmp_direct_oneone_out
        elif [[ "$proto" == "ICMP for TCP forward" && "$mode" == "Reverse" ]]; then
          [[ "$side" == "IN" ]] && icmp_reverse_oneone_in || icmp_reverse_oneone_out
        else
          add_notice "${BOLD}${YELLOW}${proto} $mode OneOne not implemented.${RESET}"
          pause
        fi
        ;;
      2)
        if [[ "$proto" == "WebSocket(ws) for TCP forward" && "$mode" == "Direct" ]]; then
          [[ "$side" == "IN" ]] && ws_direct_multiout_in || ws_direct_multiout_out
        elif [[ "$proto" == "WebSocket(ws) for TCP forward" && "$mode" == "Reverse" ]]; then
          [[ "$side" == "IN" ]] && ws_reverse_multiout_in || ws_reverse_multiout_out

        elif [[ "$proto" == "TCP for TCP forward" && "$mode" == "Direct" ]]; then
          [[ "$side" == "IN" ]] && tcp_direct_multiout_in || tcp_direct_multiout_out
        elif [[ "$proto" == "TCP for TCP forward" && "$mode" == "Reverse" ]]; then
          [[ "$side" == "IN" ]] && tcp_reverse_multiout_in || tcp_reverse_multiout_out

        elif [[ "$proto" == "QUIC for TCP forward" && "$mode" == "Direct" ]]; then
          [[ "$side" == "IN" ]] && quic_tcp_direct_multiout_in || quic_tcp_direct_multiout_out
        elif [[ "$proto" == "QUIC for TCP forward" && "$mode" == "Reverse" ]]; then
          [[ "$side" == "IN" ]] && quic_tcp_reverse_multiout_in || quic_tcp_reverse_multiout_out

        elif [[ "$proto" == "QUIC for UDP forward" && "$mode" == "Direct" ]]; then
          [[ "$side" == "IN" ]] && quic_udp_direct_multiout_in || quic_udp_direct_multiout_out
        elif [[ "$proto" == "QUIC for UDP forward" && "$mode" == "Reverse" ]]; then
          [[ "$side" == "IN" ]] && quic_udp_reverse_multiout_in || quic_udp_reverse_multiout_out

        elif [[ "$proto" == "ICMP for TCP forward" && "$mode" == "Direct" ]]; then
          [[ "$side" == "IN" ]] && icmp_direct_multiout_in || icmp_direct_multiout_out
        elif [[ "$proto" == "ICMP for TCP forward" && "$mode" == "Reverse" ]]; then
          [[ "$side" == "IN" ]] && icmp_reverse_multiout_in || icmp_reverse_multiout_out
        else
          add_notice "${BOLD}${YELLOW}${proto} $mode MultiOut not implemented.${RESET}"
          pause
        fi
        ;;
      3)
        if ((has_lb==1)); then
          if [[ "$proto" == "WebSocket(ws) for TCP forward" && "$mode" == "Direct" ]]; then
            [[ "$side" == "IN" ]] && ws_direct_lb_in || ws_direct_lb_out
          elif [[ "$proto" == "WebSocket(ws) for TCP forward" && "$mode" == "Reverse" ]]; then
            [[ "$side" == "IN" ]] && ws_reverse_lb_in || ws_reverse_lb_out
          elif [[ "$proto" == "TCP for TCP forward" && "$mode" == "Direct" ]]; then
            [[ "$side" == "IN" ]] && tcp_direct_lb_in || tcp_direct_lb_out
          else
            add_notice "${BOLD}${YELLOW}${proto} $mode Loadbalancer not implemented.${RESET}"
            pause
          fi
        else
          add_notice "${BOLD}${RED}Loadbalancer not available for this protocol.${RESET}"
          pause
        fi
        ;;
      0) return 0 ;;
      *) add_notice "${BOLD}${RED}Invalid choice in Topology Menu.${RESET}" ;;
    esac
  done
}

protocol_menu_common() {
  local side="$1"
  while true; do
    clear_screen; render_banner; render_notices; echo; render_status_block
    echo -e "${BOLD}1. WebSocket(ws) for TCP forward${RESET}"
    echo -e "${BOLD}2. TCP for TCP forward${RESET}"
    echo -e "${BOLD}3. QUIC for TCP forward${RESET}"
    echo -e "${BOLD}4. QUIC for UDP forward${RESET}"
    echo -e "${BOLD}5. ICMP for TCP forward${RESET}"
    echo -e "${BOLD}0. Back${RESET}"
    render_footer; echo

    local c proto
    c="$(read_choice "Select protocol for gost-$side: ")"
    case "$c" in
      1) proto="WebSocket(ws) for TCP forward" ;;
      2) proto="TCP for TCP forward" ;;
      3) proto="QUIC for TCP forward" ;;
      4) proto="QUIC for UDP forward" ;;
      5) proto="ICMP for TCP forward" ;;
      0) return 0 ;;
      *) add_notice "${BOLD}${RED}Invalid choice in Protocol Menu.${RESET}"; continue ;;
    esac

    mode_menu "$side" "$proto"
  done
}

main_menu() {
  while true; do
    clear_screen; render_banner; render_notices; echo; render_status_block
    echo -e "${BOLD}1. install gost${RESET}"
    echo -e "${BOLD}2. Config gost-IN Side${RESET}"
    echo -e "${BOLD}3. Config gost-OUT Side${RESET}"
    echo -e "${BOLD}4. Backup - Restore${RESET}"
    echo -e "${BOLD}5. uninstall gost${RESET}"
	echo -e "${BOLD}6. Service Management${RESET}"
    echo -e "${BOLD}0. Exit${RESET}"
    render_footer; echo

    local c
    c="$(read_choice "Select an option: ")"
    case "$c" in
      1) install_gost ;;
      2) protocol_menu_common "IN" ;;
      3) protocol_menu_common "OUT" ;;
      4) backup_restore_menu ;;
      5) uninstall_menu ;;
	  6) service_management_menu ;;
      0) clear; exit 0 ;;
      *) add_notice "${BOLD}${RED}Invalid choice in Main Menu.${RESET}" ;;
    esac
  done
}

add_notice "YOUSAFE started."
main_menu
