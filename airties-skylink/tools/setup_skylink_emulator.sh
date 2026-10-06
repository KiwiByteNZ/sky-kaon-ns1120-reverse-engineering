#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EMULATOR_FILE="$SCRIPT_DIR/mercku_skylink_emulator.lua"

ROUTER_IP=${ROUTER_IP:-192.168.50.1}
ROUTER_USER=${ROUTER_USER:-root}
ROUTER_INTERFACE=${ROUTER_INTERFACE:-br-lan}
SKYBOX_IP=${SKYBOX_IP:-90.223.243.226}
SKYLINK_IP=${SKYLINK_IP:-90.223.243.225}
SKYLINK_PREFIX=${SKYLINK_PREFIX:-29}
SKYLINK_MAC=${SKYLINK_MAC:-88:41:fc:6f:dc:52}
REMOTE_PORT=${REMOTE_PORT:-18080}

SSH_OPTIONS=(
  -o HostKeyAlgorithms=+ssh-rsa
  -o StrictHostKeyChecking=accept-new
)

if [[ ! -f "$EMULATOR_FILE" ]]; then
  echo "Missing emulator: $EMULATOR_FILE" >&2
  exit 1
fi

echo "Uploading emulator to $ROUTER_USER@$ROUTER_IP ..."
scp -O "${SSH_OPTIONS[@]}" "$EMULATOR_FILE" \
  "$ROUTER_USER@$ROUTER_IP:/tmp/mercku_skylink_emulator.lua"

echo "Configuring the temporary SkyLink identity and firewall rules ..."
ssh "${SSH_OPTIONS[@]}" "$ROUTER_USER@$ROUTER_IP" sh -s -- \
  "$ROUTER_INTERFACE" "$SKYBOX_IP" "$SKYLINK_IP" "$SKYLINK_PREFIX" \
  "$SKYLINK_MAC" "$REMOTE_PORT" <<'REMOTE_SCRIPT'
set -eu

router_interface=$1
skybox_ip=$2
skylink_ip=$3
skylink_prefix=$4
skylink_mac=$5
remote_port=$6
emulator=/tmp/mercku_skylink_emulator.lua
pid_file=/tmp/skylink-emulator.pid
log_file=/tmp/skylink-emulator.log

if [ -f "$pid_file" ]; then
  old_pid=$(sed -n '1p' "$pid_file")
  case "$old_pid" in
    ''|*[!0-9]*) ;;
    *) kill "$old_pid" 2>/dev/null || true ;;
  esac
fi

# Remove any older instance left by a partially completed setup.
for old_pid in $(pidof lua 2>/dev/null || true); do
  if tr '\000' ' ' <"/proc/$old_pid/cmdline" 2>/dev/null | \
    grep -q '^lua /tmp/mercku_skylink_emulator[.]lua'; then
    kill "$old_pid" 2>/dev/null || true
  fi
done
sleep 1

ip link set dev "$router_interface" address "$skylink_mac"
if ! ip -4 addr show dev "$router_interface" | grep -q " $skylink_ip/$skylink_prefix"; then
  ip addr add "$skylink_ip/$skylink_prefix" dev "$router_interface"
fi

# Delete obsolete variants from earlier runs.
while iptables -t nat -D PREROUTING -i "$router_interface" \
  -d "$skylink_ip/32" -p tcp --dport 80 \
  -j REDIRECT --to-ports "$remote_port" 2>/dev/null; do :; done
while iptables -D INPUT -s "$skybox_ip/32" -d "$skylink_ip/32" \
  -p tcp --dport "$remote_port" -j ACCEPT 2>/dev/null; do :; done

if ! iptables -t nat -C PREROUTING -d "$skylink_ip/32" -p tcp \
  --dport 80 -j REDIRECT --to-ports "$remote_port" 2>/dev/null; then
  iptables -t nat -I PREROUTING 1 -d "$skylink_ip/32" -p tcp \
    --dport 80 -j REDIRECT --to-ports "$remote_port"
fi

if ! iptables -C INPUT -s "$skybox_ip/32" -p tcp \
  --dport "$remote_port" -j ACCEPT 2>/dev/null; then
  iptables -I INPUT 1 -s "$skybox_ip/32" -p tcp \
    --dport "$remote_port" -j ACCEPT
fi

nohup lua "$emulator" >"$log_file" 2>&1 &
emulator_pid=$!
echo "$emulator_pid" >"$pid_file"
sleep 1

if ! kill -0 "$emulator_pid" 2>/dev/null; then
  echo "Emulator failed to start:" >&2
  sed -n '1,80p' "$log_file" >&2
  exit 1
fi

# Announce the emulated identity to the directly connected Sky box.
busybox arping -U -c 3 -I "$router_interface" \
  -s "$skylink_ip" "$skylink_ip" >/dev/null 2>&1 || true

echo "Emulator PID: $emulator_pid"
ip -br link show "$router_interface"
ip -br addr show "$router_interface"
netstat -lntp 2>/dev/null | grep ":$remote_port " || true
iptables -t nat -L PREROUTING -n -v | grep "$skylink_ip" || true
iptables -L INPUT -n -v | grep "$skybox_ip" | grep "$remote_port" || true
REMOTE_SCRIPT

echo
echo "SkyLink emulator is ready."
echo "Connect: Sky box SkyLink port -> Mercku LAN port"
echo "Capture on the router with:"
echo "  tcpdump -i $ROUTER_INTERFACE -nn -s0 -A 'host $SKYBOX_IP and tcp port 80'"
