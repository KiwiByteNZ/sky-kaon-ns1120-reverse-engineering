# AirTies Air4400SNZ SSID-processing review

Firmware: 1.0.0.9  
Target binary: `/usr/bin/mngr_unpacked` (32-bit little-endian MIPS)

## Finding: root command injection through a WPS-supplied SSID

The management daemon accepts an SSID when its byte length is from 1 through 32. The function `WlCheckSSIDValidity` at virtual address `0x457764` calls `strlen`, subtracts one, and checks only whether the result is below 32. It performs no character validation or shell escaping.

Following a successful WPS operation, the daemon creates `/tmp/savewpstakenconfig.sh`. The embedded script template at file offset `592880` is:

```sh
cli set wireless_core-0:sta_ssid $'%s'
```

The surrounding strings show the complete behavior:

```text
/tmp/savewpstakenconfig.sh
#!/bin/sh
sleep 1
cli command cfgmgr-0:begin_transaction wireless_core-0
cli set wireless_core-0:sta_ssid $'%s'
...
cli command cfgmgr-0:save
chmod 777 /tmp/savewpstakenconfig.sh; /tmp/savewpstakenconfig.sh &
```

An SSID containing a single quote can terminate the `$'...'` string and add a shell command. The management daemon and generated script run as root.

### Harmless lab proof

Configure a controlled WPS access point with this SSID, then connect the Air4400SNZ to it using WPS:

```text
X';touch /tmp/ssid_poc;#
```

The payload is 24 bytes, within the 32-byte SSID limit. If vulnerable, `/tmp/ssid_poc` will exist on the Air4400SNZ after WPS completes. Use only a disposable lab configuration because the malformed saved SSID may disrupt subsequent wireless operation.

Expected generated line:

```sh
cli set wireless_core-0:sta_ssid $'X';touch /tmp/ssid_poc;#'
```

### Exposure and impact

The confirmed sink belongs to the WPS-success configuration-saving path. Exploitation requires the Air4400SNZ to complete WPS with an attacker-controlled access point or registrar that supplies the crafted SSID. Successful exploitation provides arbitrary command execution as root and persistent configuration manipulation.

The normal web-interface join path also permits printable ASCII shell metacharacters. Its JavaScript expression is `^(?!\\x20)[\\x20-\\x7f]{0,31}[\\x21-\\x7f]$`, and server-side validation still checks only length. However, the normal station configuration function passes SSID data through wireless configuration structures rather than the identified shell-script template. Static evidence therefore confirms the WPS path; the ordinary manual/scan join path needs a live trace before claiming command execution.

### Remediation

Do not construct a shell script from WPS credentials. Call the configuration API directly with an argument vector. If compatibility requires a script, encode every byte with a strict shell-quoting routine, create the file mode `0700`, use an unpredictable root-owned path, and reject control characters. Apply the same validation server-side rather than relying on JavaScript.
