#!/usr/bin/env python3
import http.client
import re
import urllib.request

HOST = "192.168.50.131"
PORT = 49153
PATH = "/444D5276-3247-536B-7943-943bb1c5f496SkyPlay"
ACTION = '"urn:schemas-nds-com:service:SkyPlay:2#GetTransportInfo"'

VALUES = [
    ("plain-zero", b"0", b""),
    ("leading-space", b" 0", b""),
    ("trailing-space", b"0 ", b""),
    ("surrounding-space", b" \r\n0\t ", b""),
    ("comment-before", b"<!--a-->0", b""),
    ("comment-after", b"0<!--a-->", b""),
    ("comment-split", b"0<!--a-->0", b""),
    ("comment-hide-junk", b"0<!--a-->junk", b""),
    ("comment-prefix-junk", b"junk<!--a-->0", b""),
    ("pi-before", b"<?p x?>0", b""),
    ("pi-after", b"0<?p x?>", b""),
    ("pi-split", b"0<?p x?>junk", b""),
    ("child-split", b"0<x>junk</x>", b""),
    ("decimal-ref", b"&#48;", b""),
    ("hex-ref", b"&#x30;", b""),
    ("split-refs", b"&#4;8", b""),
    ("cdata-zero", b"<![CDATA[0]]>", b""),
    ("split-cdata", b"<![CDATA[0]]><![CDATA[]]>", b""),
    ("text-cdata-text", b"<![CDATA[]]>0<![CDATA[]]>", b""),
    ("internal-entity", b"&z;", b'<!DOCTYPE x [<!ENTITY z "0">]>'),
    ("leading-zero", b"00", b""),
    ("plus-zero", b"+0", b""),
    ("minus-zero", b"-0", b""),
    ("zero-junk", b"0junk", b""),
    ("junk-zero", b"junk0", b""),
    ("empty", b"", b""),
]


def request(value, doctype):
    body = (
        b'<?xml version="1.0"?>' + doctype
        + b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
        + b'<s:Body><u:GetTransportInfo xmlns:u="urn:schemas-nds-com:service:SkyPlay:2">'
        + b'<InstanceID>' + value + b'</InstanceID>'
        + b'</u:GetTransportInfo></s:Body></s:Envelope>'
    )
    connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
    connection.request("POST", PATH, body=body, headers={
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": ACTION,
    })
    response = connection.getresponse()
    data = response.read()
    connection.close()
    code = re.search(br"<errorCode>([^<]+)", data)
    description = re.search(br"<errorDescription>([^<]+)", data)
    state = re.search(br"<CurrentTransportState>([^<]+)", data)
    detail = (
        state.group(1) if state else
        (code.group(1) + b" " + description.group(1) if code and description else b"no-detail")
    )
    return response.status, detail.decode("latin1", "replace")


for name, value, doctype in VALUES:
    try:
        status, detail = request(value, doctype)
        print(f"{name:20s} HTTP={status} result={detail}")
    except Exception as error:
        print(f"{name:20s} FAILURE={error}")
    with urllib.request.urlopen(f"http://{HOST}:{PORT}/description0.xml", timeout=3) as health:
        if health.status != 200:
            raise SystemExit(f"health failure after {name}: HTTP {health.status}")

print("equivalence matrix complete")
