# SkyLink emulator / Sky-box research handoff

Updated: 2026-09-20 (UTC)

## Scope and current state

- Authorized closed-lab testing of a Sky box using a lab router as an AirTies/SkyLink
  emulator.
- The emulator is currently running on the lab router with the **normal** profile.
- Do not stop it unnecessarily. Mutating SkyLink operations (`join`, `set`, `reset`, `reboot`, and `upgrade`) remain disabled.
- Router login credentials are deliberately not recorded in this file.

## Network map

- Lab-router management address: `192.168.50.1`
- Sky box normal LAN address: `192.168.50.197`
- Sky box SkyLink-management address: `90.223.243.226`
- Emulated SkyLink address: `90.223.243.225/29`
- Research workstation / callback listener: `192.168.0.163`
- Sky box MAC: `94:3b:b1:c5:f4:96`
- Real SkyLink MAC observed: `88:41:fc:6f:dc:52`
- The router bridge was temporarily configured to present the SkyLink MAC and address.

Important ICMP interpretation:

- Evidence of a Sky-box callback: `192.168.50.197 -> 192.168.0.163`, ICMP echo **request**.
- `192.168.0.163 -> 192.168.50.197` is merely the workstation pinging the box and is not command-execution evidence.

## Emulator files

- `skylink_emulator.lua` — HTTP emulator and test profiles.
- `setup_skylink_emulator.sh` — installs/configures it on the lab router.
- `status_skylink_emulator.sh` — checks status.
- `stop_skylink_emulator.sh` — stops and removes the temporary setup.
- `SKYLINK_EMULATOR_README.md` — operating instructions.

Router runtime paths:

- `/tmp/skylink_emulator.lua`
- `/tmp/skylink-emulator.pid`
- `/tmp/skylink-emulator.log`
- Lua listens on TCP `18080`; the router redirects `90.223.243.225:80` to it.

Expected startup log:

```text
SkyLink emulator listening on 0.0.0.0:18080 profile=normal
```

## Observed SkyLink protocol

The Sky box polls the emulator over HTTP/1.0:

```http
GET /stbadmin?info HTTP/1.0
Host: 90.223.243.225
Accept: */*
```

It then requests `/stbadmin?capabilities`. Read-only responses use quoted `key="value"` lines. A normal `info` response identifies an AirTies `Sky Wireless Connector`, protocol 2, and firmware `1.0.0.9`.

## Completed firmware-field command-injection probes

### Literal-space probe

Delivered twice and fully acknowledged:

```text
firmware="1.0.0.9;ping -c1 192.168.0.163;#"
```

The displayed/stored value appeared truncated. No ICMP request from the Sky box was observed, and the box continued to request `capabilities`.

### No-literal-space probe

Delivered twice and fully acknowledged:

```text
firmware="1.0.0.9;ping${IFS}-c1${IFS}192.168.0.163;#"
```

Again, no ICMP callback occurred and the box continued normally. The UI/display showed:

```text
1.0.0.9;ping${IF
```

That is exactly 16 characters, strongly indicating a fixed-width display or stored firmware field. Packet capture proved the full HTTP value reached the box; it does not prove the full value survived the box's internal copy.

Conclusion: no command execution was demonstrated through the `firmware` field in this startup path. The field currently appears to be treated as data and/or truncated to 16 characters internally.

## Other completed emulator tests

- SSID command-substitution-shaped value was delivered; no callback was seen.
- Quoted SSID was parsed without a crash.
- A combined test appended `;ping${IFS}-c1${IFS}192.168.0.163;#` to every selected descriptive/status field. The complete response was fetched and acknowledged twice, parsing continued to `capabilities`, and no ICMP callback was observed.
- A second combined test appended `$(ping -c1 192.168.0.163)` to those fields. It was also fetched and acknowledged twice, followed by `capabilities`, with no ICMP callback during the exchange or observation period.
- A final one-shot test appended `$(ping -c1 192.168.0.163)` to every `info` field, including `protocol`, MAC, management addressing, DHCP, IP, subnet, gateway, and DNS. The response was fetched and acknowledged twice, but the box did not continue to `capabilities`. No ICMP callback occurred. This is consistent with early strict-field validation failure and does not demonstrate command execution.
- Combined tests are only coarse screens: a negative result does not independently clear each field, especially where numeric/status parsers may reject modified values.
- Confirmed CR/LF record injection and duplicate-key precedence: the final `joining` value was changed so the response ended with `joining="0"` followed by an injected `firmware="MARKER"` record. The box fetched it twice, continued to `capabilities`, and its UI displayed `MARKER` instead of the earlier legitimate `firmware="1.0.0.9"`. Therefore the client accepts CR/LF-created records and the last duplicate key wins. Security impact depends on whether an untrusted source can control a response value that the real SkyLink/darwind server emits without escaping.
- Confirmed the same override when the injected record originated specifically inside the emulated `ssid` value. The 21-byte raw value `X"\r\nfirmware="MARKER` produced `ssid="X"` followed by `firmware="MARKER"`; the box continued to `capabilities` and displayed firmware `MARKER`. This fits within the 32-byte 802.11 SSID limit. It proves the Sky-box client is vulnerable to an unescaped SSID-position record, but a real wireless attack path still requires proving that genuine SkyLink firmware accepts such an SSID and emits its CR/LF bytes without filtering or escaping.
- Tested operational redirection using the SSID-position value `X"\r\nmgmt_ip="192.168.0.163`, also within the SSID size limit. The injected duplicate was delivered twice, but subsequent `capabilities` requests continued to `90.223.243.225`; no TCP/80 attempt to `192.168.0.163` was observed. Thus `mgmt_ip` duplication did not redirect the active management sequence.
- Comma, CR/LF, and oversized SSID profiles exist for controlled parser testing; some require a Sky-box reboot to exercise the startup path.
- Restore the `normal` profile after every probe.

## Packet capture

Useful router-side capture filter:

```sh
tcpdump -i br-lan -nn -s0 -A \
  '((host 90.223.243.226 or host 192.168.50.197) and tcp port 80) or (icmp and host 192.168.0.163)'
```

## Firmware reverse-engineering context

Extracted filesystem:

```text
/home/user/Documents/Sky/Firmwaredump/_backup.bin.extracted/squashfs-root
```

Relevant daemon:

```text
/home/user/Documents/Sky/Firmwaredump/_backup.bin.extracted/squashfs-root/bin/darwind
```

Known handler names include `info`, `capabilities`, `survey`, `networks`, `join`, `set`, `reset`, `reboot`, `upgrade`, and `settings.type`. Static review suggested the CGI relay forwards `QUERY_STRING` (including a NUL) to a Unix socket. A query longer than roughly 1024 bytes may warrant focused review for termination/over-read behavior. Response fields are not escaped, and the CGI variable parser may have malformed-percent and prefix-matching edge cases. These are leads, not confirmed vulnerabilities.

## Recommended next session

1. Confirm the emulator status and that the active profile is `normal`.
2. Continue static analysis of the Sky-box consumer that parses `/stbadmin?info`, specifically locate the 16-byte firmware destination and all later uses.
3. Prefer short, harmless parser canaries and monitor box health plus traffic. Do not infer execution from UI truncation alone.
4. Preserve captures showing the exact response, ACK, subsequent request, and callback direction.

## Stateful workflow emulator

Implemented and deployed on 2026-09-21. The normal profile now safely simulates
`survey`, `networks`, `join`, `settings.type`, and `set` in memory. Survey and
join expose timed `STA_SCANNING`/`STA_CONNECTING` transitions before returning
to `STA_CONNECTED`; the network list contains `TestNetwork` and `LabGuest`.
Submitted Wi-Fi keys are not stored and are redacted from logs. DHCP/static
values alter only the emulator response state and never the router network.
`reset`, `reboot`, and `upgrade` remain blocked for later explicit testing.

## Authentic SkyLink workflow capture (2026-09-21)

The two occupied lab-router LAN sockets had to be isolated from the ordinary
LAN;
placing both devices on the original flat VLAN caused the Sky box to show only
Automatic DHCP and produced unreliable same-switch-port forwarding. The working
temporary topology is:

```text
SkyLink LAN socket (switch port 0, VLAN 10) -- br-skylink --
Sky box LAN socket (switch port 1, VLAN 11)
CPU switch port 6 is tagged in VLANs 10 and 11.
```

`br-skylink` bridges `eth0.10` and `eth0.11`. This made the Sky box show the
Wireless setup UI and allowed a complete, reliable capture. The completed pcap
is `real-skylink-setup.pcap` in this workspace.

Authentic request sequence:

```text
GET /stbadmin?info HTTP/1.0
GET /stbadmin?capabilities HTTP/1.0
GET /stbadmin?survey HTTP/1.0
(poll GET /stbadmin?info while surveying="1")
GET /stbadmin?networks&count="99" HTTP/1.0
GET /stbadmin?join&ssid="Lab_Guest"&security="open"&encryption="none"&key="" HTTP/1.0
(poll GET /stbadmin?info while joining="1")
GET /stbadmin?capabilities HTTP/1.0
```

Observed real-device state transition:

```text
state="NOCONF", surveying="0", joining="0"
state="NOCONF", surveying="1", joining="0"
state="JOIN",   surveying="0", joining="1"
state="AUTH",   surveying="0", joining="0"
```

After association with the temporary open `Lab_Guest` network, the real
SkyLink reported DHCP address `192.168.50.166` and gateway `192.168.50.1`.
The guest profile was enabled in the running UCI state but was not committed.
The temporary VLAN bridge remains active until explicitly restored or the
router is rebooted.

The emulator was subsequently updated and restarted on `br-skylink`. Its
normal profile now reproduces the authentic initial values, capabilities,
survey polling, `networks&count="99"`, and the timed `NOCONF -> JOIN -> AUTH`
transition. The physical SkyLink leg (`eth0.10`) was removed from `br-skylink`
to prevent an address conflict; the Sky-box leg (`eth0.11`) remains attached.
To return to the real SkyLink later, stop the emulator using
`ROUTER_INTERFACE=br-skylink`, then run
`brctl addif br-skylink eth0.10` on the lab router.

### Confirmed scan-list record injection

The emulator returned one scan record whose raw SSID was
`X"\r\nssid="INJECTED`. The Sky-box UI displayed two selectable entries, `X`
and `INJECTED`. Selecting the synthetic entry caused the box to issue:

```text
GET /stbadmin?join&ssid="INJECTED"&security="open"&encryption="none"&key=""
```

This confirms that CR/LF inside an unescaped scanned SSID can create an extra
trusted network record and drive the join workflow. Command-substitution
canaries placed individually in `ssid`, `channel`, `mode`, `security`,
`encryption`, and `strength` produced no seven-ping callback. Invalid
`security` and `encryption` values were normalized to empty strings in the
join request. Establishing an over-the-air attack path still requires testing
whether the genuine SkyLink preserves CR/LF bytes from an 802.11 SSID in its
`networks` response.

Control-character isolation showed that both bare LF (`0x0A`) and bare CR
(`0x0D`) independently create additional displayed scan records; a CRLF pair
is not required. Selecting the bare-CR-created `CR_INJECTED` entry produced a
normal join request with `ssid="CR_INJECTED"`, `security="open"`, and
`encryption="none"`, followed by the simulated join completion. Horizontal
tab (`0x09`), vertical tab (`0x0B`), and form feed (`0x0C`) remained within a
single SSID, rendered invisibly in the UI, and were preserved in join requests
as `%09`, `%0B`, and `%0C` respectively. The bare-LF display injection was
confirmed, but its synthetic entry was not selected during that run.

A same-line delimiter test is also confirmed. The raw SSID
`COMMA_A",ssid="COMMA_INJECTED` caused the UI to display both `COMMA_A` and
`COMMA_INJECTED`, without CR or LF. Selecting the synthetic entry produced a
normal join request for `ssid="COMMA_INJECTED"` with attacker-supplied open
security attributes and completed the simulated join. This shows that the
scan parser also treats an embedded quote/comma/field sequence as protocol
structure. Because quote and comma are ordinary legal SSID bytes, this may be
an easier over-the-air input path than control characters, subject to genuine
SkyLink response escaping behavior.

A literal NUL test displayed and joined only the prefix `NUL_A` from the raw
SSID `NUL_A\0NUL_B`, confirming C-string truncation of the stored value.

Count-field tests showed `nets_returned` controls the number of selectable
slots, while `nets_found` controls how many names are treated as valid.
Underreporting caused extra supplied rows to be ignored. Overreporting by one
created selectable blank entries; selecting one issued a join with empty
fields and was rejected by the emulator. With `nets_found="1"` and
`nets_returned="2"`, the second entry had a blank SSID but inherited
`wpa2-psk`/`aes` and accepted password input. A nonnumeric returned count
displayed no networks. A single bounded negative test using
`nets_returned="-1"` caused the wireless search UI to stop working; after the
box fetched `networks&count="99"`, no further SkyLink HTTP requests appeared.
This is consistent with a search-component hang or crash, not yet proof of a
whole-box crash. The emulator was immediately restored to its normal profile.
The wireless-search hang persisted after leaving/reopening setup and the user
rebooted the Sky box to recover, confirming a reboot-required denial of service
for that UI path in this test.

An SSID-to-global-field injection was confirmed using the legal-size raw value
`COUNT_A"\nnets_returned="1`. Although the legitimate response header declared
two returned networks and supplied two rows, the later SSID-injected count won;
the UI displayed only `COUNT_A` and suppressed `TestNetwork`. Selecting it
issued a normal join for `COUNT_A` with `security="open"` and
`encryption="none"`, and completed the simulated join. Thus an SSID can cross
record boundaries, override a global parser-control field, truncate the whole
scan list, and remain selectable.
