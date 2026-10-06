# Sky Kaon NS1120 reverse engineering

Research notes and utilities for the New Zealand Sky Kaon NS1120 set-top box
and the AirTies Air4400SNZ Sky Wireless Connector.

## Contents

- `kaon/tools/kaon_remote.py` — discovers and calls the Kaon SkyPlay/SkyRC
  UPnP services.
- `kaon/tools/upnp_xml_equivalence.py` — compares UPnP XML response behaviour.
- `kaon/tools/upnp_xml_fuzz.py` — controlled UPnP XML parser testing.
- `airties-skylink/tools/skylink_emulator.lua` — stateful emulator for
  the SkyLink management protocol.
- `airties-skylink/tools/setup_skylink_emulator.sh` — installs/configures the
  emulator on the lab router used during testing.
- `airties-skylink/tools/status_skylink_emulator.sh` and
  `stop_skylink_emulator.sh` — status and cleanup helpers.
- `airties-skylink/notes/` — findings, setup instructions, and session notes.
- `airties-skylink/captures/real-skylink-setup.pcap` — a reference capture of
  the genuine connector setup exchange.

## Devices covered

- Sky set-top box: Kaon NS1120
- Wireless connector: AirTies Air4400SNZ, marketed as the Sky Wireless
  Connector

The emulator tooling was developed in a controlled lab environment. Its
router-specific defaults and network addresses should be reviewed before use.
Restore the `normal` emulator profile after parser tests.

## Responsible use

Use this material only with hardware and networks that you own or are
authorised to test. The repository documents interoperability and security
research; it does not include proprietary firmware dumps, customer recordings,
or credentials.

## Contributing

Reproducible findings for the Kaon NS1120 or AirTies Air4400SNZ are welcome.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

This is an independent community research project and is not affiliated with
Sky, Kaon, or AirTies.
