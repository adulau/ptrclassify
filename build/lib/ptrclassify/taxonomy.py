"""Taxonomy used by ptrclassify.

The classifier intentionally returns multiple orthogonal labels.  A host can be,
for example, allocation:dynamic + access:mobile + translation:nat + role:customer.
"""

TAXONOMY = {
    "allocation": {
        "dynamic": "Address appears dynamically assigned or drawn from a pool.",
        "static": "Hostname explicitly indicates static/fixed assignment.",
        "reserved": "Hostname indicates reserved/unused address space.",
    },
    "access": {
        "residential": "Residential/consumer access network.",
        "business": "Business/enterprise access circuit.",
        "mobile": "Mobile/cellular access.",
        "cable": "Cable/HFC access network.",
        "dsl": "DSL/xDSL access network.",
        "fiber": "Fiber/FTTH access network.",
        "wireless": "Wi-Fi/WLAN or fixed-wireless access.",
        "broadband": "Generic broadband access when medium is unclear.",
        "dialup-ppp": "PPP/dial-like subscriber addressing.",
    },
    "translation": {
        "nat": "Address naming explicitly indicates NAT.",
        "cgnat": "Address naming explicitly indicates carrier-grade/shared NAT.",
    },
    "role": {
        "customer": "Customer/subscriber endpoint naming.",
        "router": "Router or network forwarding infrastructure.",
        "broadband-aggregation": "BRAS/BNG/access aggregation infrastructure.",
        "loopback-interface": "Router/network-device loopback interface.",
        "server": "Server/service host naming.",
        "virtual-machine": "Virtual-machine/compute instance naming.",
        "vpn": "VPN endpoint/gateway naming.",
        "voip": "Voice-over-IP infrastructure/service.",
        "eduroam": "eduroam wireless client/network context.",
    },
    "hosting": {
        "cloud": "Public cloud compute infrastructure.",
        "datacenter": "Datacenter/hosting infrastructure.",
        "hosting": "Web/VPS/hosting-provider infrastructure.",
        "cdn": "Content delivery network edge/server.",
    },
    "network": {
        "anycast": "Anycast service addressing.",
        "dedicated-internet": "Dedicated Internet Access (DIA) circuit.",
    },
    "organization": {
        "education": "Educational/research organization namespace.",
        "government": "Government namespace.",
        "military": "Military namespace.",
        "enterprise": "Named enterprise/corporate namespace.",
    },
    "provider": {},
    "naming": {
        "ip-encoded": "Hostname embeds the IP address or a direct textual transform of it.",
        "generic-reverse": "Generic provider-generated reverse name with little host semantics.",
    },
    "dns": {
        "cname": "Input is a CNAME in reverse DNS rather than the final PTR target.",
    },
}
