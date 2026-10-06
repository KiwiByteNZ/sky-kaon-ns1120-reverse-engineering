# Mercku SkyLink emulator

This kit makes the Mercku temporarily emulate the AirTies SkyLink management
interface used by the directly connected Sky box.

## Topology

```text
Sky box SkyLink Ethernet port -> Mercku LAN port
```

Do not connect the physical AirTies SkyLink while its MAC address is being
emulated.

## Start after a reboot

From this directory:

```bash
chmod +x setup_skylink_emulator.sh status_skylink_emulator.sh stop_skylink_emulator.sh
./setup_skylink_emulator.sh
```

Enter the Mercku root password when SCP and SSH request it. The known lab
password is not embedded in these files.

The script installs only temporary state. Run it again after either the Mercku
or its `/tmp` filesystem has been reset.

## Check status

```bash
./status_skylink_emulator.sh
```

## Capture requests

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.50.1
tcpdump -i br-lan -nn -s0 -A 'host 90.223.243.226 and tcp port 80'
```

## Stop and restore the Mercku identity

```bash
./stop_skylink_emulator.sh
```

A Mercku reboot also removes the running emulator, temporary address and
firewall rules. The setup script changes `br-lan` to the AirTies MAC, so use the
stop script when you want to restore the original MAC without rebooting.

## Defaults and overrides

Defaults:

```text
Router:       192.168.50.1
SkyLink IP:   90.223.243.225/29
SkyLink MAC:  88:41:fc:6f:dc:52
Sky box IP:   90.223.243.226
Internal port: 18080
```

Settings can be overridden for one run with environment variables, for
example:

```bash
ROUTER_IP=192.168.50.1 SKYLINK_MAC=88:41:fc:6f:dc:52 ./setup_skylink_emulator.sh
```

The emulator keeps an in-memory setup state. `survey`, `networks`, `join`,
`settings.type`, and `set` are simulated without changing the Mercku radio or
network configuration. `reset`, `reboot`, and `upgrade` remain blocked.
