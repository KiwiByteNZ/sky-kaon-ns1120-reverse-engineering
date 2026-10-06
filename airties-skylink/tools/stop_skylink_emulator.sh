#!/usr/bin/env bash
set -euo pipefail

ROUTER_IP=${ROUTER_IP:-192.168.50.1}
ROUTER_USER=${ROUTER_USER:-root}
ROUTER_INTERFACE=${ROUTER_INTERFACE:-br-lan}
SKYBOX_IP=${SKYBOX_IP:-90.223.243.226}
SKYLINK_IP=${SKYLINK_IP:-90.223.243.225}
SKYLINK_PREFIX=${SKYLINK_PREFIX:-29}
REMOTE_PORT=${REMOTE_PORT:-18080}
MERCKU_ORIGINAL_MAC=${MERCKU_ORIGINAL_MAC:-f8:27:2e:0d:7a:a8}

ssh -o HostKeyAlgorithms=+ssh-rsa -o StrictHostKeyChecking=accept-new \
  "$ROUTER_USER@$ROUTER_IP" sh -s -- \
  "$ROUTER_INTERFACE" "$SKYBOX_IP" "$SKYLINK_IP" "$SKYLINK_PREFIX" \
  "$REMOTE_PORT" "$MERCKU_ORIGINAL_MAC" <<'REMOTE_SCRIPT'
set -eu

router_interface=$1
skybox_ip=$2
skylink_ip=$3
skylink_prefix=$4
remote_port=$5
original_mac=$6

if [ -f /tmp/skylink-emulator.pid ]; then
  emulator_pid=$(sed -n '1p' /tmp/skylink-emulator.pid)
  case "$emulator_pid" in
    ''|*[!0-9]*) ;;
    *) kill "$emulator_pid" 2>/dev/null || true ;;
  esac
fi

for emulator_pid in $(pidof lua 2>/dev/null || true); do
  if tr '\000' ' ' <"/proc/$emulator_pid/cmdline" 2>/dev/null | \
    grep -q '^lua /tmp/mercku_skylink_emulator[.]lua'; then
    kill "$emulator_pid" 2>/dev/null || true
  fi
done

while iptables -t nat -D PREROUTING -d "$skylink_ip/32" -p tcp \
  --dport 80 -j REDIRECT --to-ports "$remote_port" 2>/dev/null; do :; done
while iptables -D INPUT -s "$skybox_ip/32" -p tcp \
  --dport "$remote_port" -j ACCEPT 2>/dev/null; do :; done

ip addr del "$skylink_ip/$skylink_prefix" dev "$router_interface" 2>/dev/null || true
ip link set dev "$router_interface" address "$original_mac"
rm -f /tmp/skylink-emulator.pid /tmp/skylink-emulator.log \
  /tmp/mercku_skylink_emulator.lua

echo "SkyLink emulator stopped."
ip -br link show "$router_interface"
ip -br addr show "$router_interface"
REMOTE_SCRIPT
