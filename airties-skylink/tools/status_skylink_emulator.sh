#!/usr/bin/env bash
set -euo pipefail

ROUTER_IP=${ROUTER_IP:-192.168.50.1}
ROUTER_USER=${ROUTER_USER:-root}
SKYBOX_IP=${SKYBOX_IP:-90.223.243.226}
SKYLINK_IP=${SKYLINK_IP:-90.223.243.225}
REMOTE_PORT=${REMOTE_PORT:-18080}

ssh -o HostKeyAlgorithms=+ssh-rsa -o StrictHostKeyChecking=accept-new \
  "$ROUTER_USER@$ROUTER_IP" sh -s -- \
  "$SKYBOX_IP" "$SKYLINK_IP" "$REMOTE_PORT" <<'REMOTE_SCRIPT'
skybox_ip=$1
skylink_ip=$2
remote_port=$3

echo "Interface:"
ip -br link show br-lan
ip -br addr show br-lan
echo
echo "Listener:"
netstat -lntp 2>/dev/null | grep ":$remote_port " || echo "NOT RUNNING"
echo
echo "NAT rule:"
iptables -t nat -L PREROUTING -n -v | grep "$skylink_ip" || echo "MISSING"
echo
echo "Input rule:"
iptables -L INPUT -n -v | grep "$skybox_ip" | grep "$remote_port" || echo "MISSING"
echo
echo "Sky-box neighbour:"
ip neigh show | grep "$skybox_ip" || echo "NOT SEEN"
echo
echo "Emulator log:"
tail -30 /tmp/skylink-emulator.log 2>/dev/null || true
REMOTE_SCRIPT

