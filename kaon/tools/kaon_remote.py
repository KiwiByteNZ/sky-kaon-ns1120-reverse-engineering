#!/usr/bin/env python3
"""Small command-line remote for the Kaon NS1120 SkyPlay/SkyRC services."""
import argparse
import html
import re
import subprocess

HOST = "192.168.50.131"
BASE = f"http://{HOST}:49153"
AVT = BASE + "/444D5276-3247-536B-7943-943bb1c5f496SkyPlay"
RC = BASE + "/444D5276-3247-536B-7943-943bb1c5f496SkyRC"

def call(url, service, action, args=""):
    envelope = f'''<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:{action} xmlns:u="{service}">{args}</u:{action}></s:Body></s:Envelope>'''.encode()
    result = subprocess.run(["curl", "-sS", "--max-time", "5", "-w", "\n__HTTP__%{http_code}", "-H", 'Content-Type: text/xml; charset="utf-8"', "-H", f'SOAPACTION: "{service}#{action}"', "--data-binary", envelope.decode(), url], capture_output=True, text=True)
    body, _, status = result.stdout.rpartition("\n__HTTP__")
    print(f"HTTP {status or 000}")
    print(re.sub(r"<[^>]+>", " ", html.unescape(body)).strip())

def main():
    p = argparse.ArgumentParser(description="Kaon NS1120 network remote")
    p.add_argument("action", choices=["status", "media", "play", "pause", "stop", "next", "previous", "seek"])
    p.add_argument("--target", default=HOST)
    p.add_argument("--seconds", type=int, default=0, help="seek offset, when supported")
    a = p.parse_args()
    global AVT
    AVT = f"http://{a.target}:49153/444D5276-3247-536B-7943-943bb1c5f496SkyPlay"
    if a.action == "status":
        call(AVT, "urn:schemas-nds-com:service:SkyPlay:2", "GetTransportInfo", "<InstanceID>0</InstanceID>")
    elif a.action == "media":
        call(AVT, "urn:schemas-nds-com:service:SkyPlay:2", "GetMediaInfo", "<InstanceID>0</InstanceID>")
    elif a.action == "seek":
        call(AVT, "urn:schemas-nds-com:service:SkyPlay:2", "Seek", f"<InstanceID>0</InstanceID><Unit>REL_TIME</Unit><Target>00:00:{a.seconds:02d}</Target>")
    else:
        call(AVT, "urn:schemas-nds-com:service:SkyPlay:2", a.action.title(), "<InstanceID>0</InstanceID><Speed>1</Speed>" if a.action == "play" else "<InstanceID>0</InstanceID>")

if __name__ == "__main__":
    main()
