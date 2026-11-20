# security.py - turns a scan into a list of problems ("findings") and a score out of 100
#
# server.py calls this after every scan:
#     report = security.assess(result, previous_scan)
#
# Where the rules come from:
#     - the risky ports, how bad they are, and the scoring are all in
#       vulnerability_identifier.py (COMMON_PORTS, PLAIN_ENGLISH, RISK_SCORES)
#     - this file adds a few extra checks that aren't about one port:
#       UPnP on the router, remote management, devices we couldn't identify,
#       and devices that are new since the last scan
#
# Each finding looks like this:
#     {"severity": "critical" / "high" / "medium" / "low",
#      "ip": "192.168.1.1", "device": "Router",
#      "title": what's wrong, "why": why it matters, "fix": what to do,
#      "action": the fix in a few words, "tech": technical note,
#      "details": {"weaknesses": [...], "remediations": [...]}}
#
# It also adds "is_new", "issues" and "score" to every device.
# If a device has broken data we just skip it, so this never crashes the scan.

# used to clean up company names (remove "Inc." etc.)
import re

# our teammate's port list and scoring
import vulnerability_identifier as vi

# score ranges and their names, highest first: 90+ is "excellent", 80+ is "good", and so on
BANDS = [(90, "excellent"), (80, "good"), (70, "fair"), (60, "poor"), (0, "at_risk")]
# used to sort findings so the worst ones come first
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


#
# Function: device_key - An ID for a device that stays the same between scans: its MAC address, or its IP if we don't have the MAC.
# Input argument: d - one device (a dictionary from scanner.py)
# Output argument: none
# Return: the device's ID, e.g. "AA:BB:CC:11:22:33" or "ip:192.168.1.9"
# Dependencies: none
#
def device_key(d):
    # MACs don't change, IPs sometimes do
    mac = (d.get("mac") or "").upper()
    # e.g. "AA:BB:CC:11:22:33" or "ip:192.168.1.9"
    return mac if mac else "ip:" + str(d.get("ip"))


#
# Function: _maker - Shorten company names, e.g. "Intel Corporate" -> "Intel".
# Input argument: v - a company name
# Output argument: none
# Return: the shorter company name
# Dependencies: re - I, sub
#
def _maker(v):
    v = re.sub(r",?\s*(Inc\.?|Ltd\.?|Limited|Corporation|Corporate|Corp\.?|Co\.?)\s*$", "", str(v), flags=re.I)
    # remove leftover spaces and commas
    return v.strip(" ,")


#
# Function: _name - The best name we have for a device, to show the user.
# Input argument: d - one device (a dictionary from scanner.py)
#                 names - the names the user gave their devices, {device id: name} (optional)
# Output argument: none
# Return: the best name we have for the device
# Dependencies: _maker, device_key
#
def _name(d, names=None):
    # names the user typed in on the dashboard
    names = names or {}
    # 1. the user's own name for it
    return (names.get(device_key(d))
            # 2. the name it gave itself
            or d.get("hostname")
            # 3. its model (from Bonjour)
            or d.get("mdns_model")
            # 4. "Your router"
            or ("Your router" if d.get("is_router") else None)
            # 5. e.g. "Intel device"
            or (f"{_maker(d.get('vendor'))} device" if d.get("vendor") else None)
            # 6. last resort
            or f"Unknown device ({d.get('ip')})")


#
# Function: check_device - Go through one device and give back the list of problems we found on it.
# Input argument: d - one device (a dictionary from scanner.py)
#                 names - the names the user gave their devices, {device id: name} (optional)
# Output argument: none
# Return: a list of findings for this device
# Dependencies: vulnerability_identifier.py - COMMON_PORTS, PLAIN_ENGLISH.get, open_known_ports; _name
#
def check_device(d, names=None):
    # the findings for this device
    found = []
    # phone, computer, tv_media...
    cat = d.get("category") or "unknown"
    name = _name(d, names)

    #
    # Function: add - Small helper so every finding has the same fields.
    # Input argument: sev - how urgent it is: critical, high, medium or low
    #                 title - what's wrong, in one line
    #                 why - the reason, shown on the web page
    #                 fix - what to do about it
    #                 action - the fix in a few words
    #                 tech - the technical note (optional)
    #                 details - extra details about the error
    # Output argument: found (from check_device) - the finding gets added
    # Return: none
    # Dependencies: none
    #
    def add(sev, title, why, fix, action, tech="", details=None):
        found.append({"severity": sev, "ip": d.get("ip"), "device": name, "title": title,
                      "why": why, "fix": fix, "action": action, "tech": tech, "details": details or {}})

    # 1. risky open ports, using the vulnerability list
    # only the open ports that are on the risky list
    for port in vi.open_known_ports(d):
        # the technical info about this port
        info = vi.COMMON_PORTS[port]
        # the normal-words version (with a backup just in case)
        plain = vi.PLAIN_ENGLISH.get(port) or {
            "title": f"A connection point that needs care is open ({info.get('service', port)})",
            "why": info.get("description", ""),
            "fix": "Keep the device updated and switch this off if you don't use it.",
            "action": f"Check why {info.get('service', 'this')} is turned on",
        }
        # "Critical" -> "critical"
        add(str(info.get("severity", "low")).lower(),
            plain["title"], plain["why"], plain["fix"], plain["action"],
            tech=f"{info.get('name', '')} ({info.get('service', '')}), port {port}/{info.get('protocol', 'tcp')}. "
                 # e.g. "Telnet (TELNET), port 23/tcp. ..."
                 f"{info.get('description', '')}",
            details={"weaknesses": info.get("vulnerabilities", []),
                     "remediations": info.get("remediations", [])})

    # 2. router checks that aren't about one port
    if d.get("is_router"):
        # what the router announced about itself over UPnP
        ssdp = (d.get("ssdp") or "").lower()
        # these words mean UPnP port opening is on
        if "internetgatewaydevice" in ssdp or "wanipconnection" in ssdp:
            add("medium", "Your router lets devices open doors to the internet by themselves",
                "Any app or gadget on your Wi-Fi can open a way in from the internet without asking you. "
                "That's handy for games, but a hacked gadget can use it too.",
                "Log in to your router (the address is usually on a sticker on it) and switch off \"UPnP\". "
                "If online gaming or video calls stop working afterwards, you can switch it back on.",
                "Turn off UPnP on the router",
                "UPnP Internet Gateway Device is enabled on the router.")
        # its open ports as numbers
        ports = {int(p) for p in d.get("open_ports") or [] if str(p).isdigit()}
        # "&" means "are any of these in both sets"
        if ports & {8080, 8443}:
            add("low", "Your router may be controllable from outside your home",
                "Your router has an extra settings page open. Sometimes that means it can be "
                "controlled from the internet, not just from your home.",
                "Log in to your router and make sure \"Remote management\" (or \"Remote access\") is "
                "switched off, unless you need it.",
                "Turn off Remote Management on the router",
                "Additional admin interface on port 8080/8443; check remote management settings.")

    # 3. devices we couldn't figure out
    if cat == "unknown":
        add("low", "We couldn't tell what this device is",
            "It's probably something you own, but it's worth checking in case someone is using "
            "your Wi-Fi without asking.",
            "Open the device in the list to see who made it. If you recognise it, give it a "
            "name so it's easy to spot next time. If you don't, change your Wi-Fi password.",
            "Check that you recognise it",
            "Device type could not be identified.")
    return found


#
# Function: assess - Build the safety report for a scan. Changes `result` (adds "report" and per-device info) and returns the report.
# Input argument: result - the scan results (a dictionary)
#                 previous - the last saved scan of the same network, or None
#                 names - the names the user gave their devices, {device id: name} (optional)
# Output argument: result - gets a "report", and every device gets "is_new", "issues" and "score"
# Return: the report: {score, band, counts, findings, gone, first_scan, compared_to}
# Dependencies: vulnerability_identifier.py - host_score, score_hosts; _name, check_device, device_key
#
def assess(result, previous=None, names=None):
    # ignore anything broken
    devices = [d for d in (result.get("devices") or []) if isinstance(d, dict)]
    names = names or {}

    # compare with the last scan of this network to find new and missing devices
    prev_devices = [d for d in ((previous or {}).get("devices") or []) if isinstance(d, dict)]
    # IDs of last time's devices
    prev_keys = {device_key(d) for d in prev_devices}
    # IDs of this time's devices
    now_keys = {device_key(d) for d in devices}
    # nothing to compare with the first time
    first_scan = previous is None

    # all findings, and each device's list of severities (for the score)
    findings, per_host = [], []
    for d in devices:
        try:
            # wasn't here last time
            d["is_new"] = (not first_scan) and device_key(d) not in prev_keys
            issues = check_device(d, names)
            # new devices get their own finding
            if d["is_new"]:
                # a new device we can't identify is more worrying
                unknown = d.get("category") == "unknown"
                issues.append({"severity": "medium" if unknown else "low", "ip": d.get("ip"),
                               "device": _name(d, names),
                               "title": "A new device joined your Wi-Fi",
                               "why": "It wasn't here the last time you scanned. That's normal for a new phone or "
                                      "a visitor, but worth a quick check.",
                               "fix": "If you know what it is, give it a name so it's easy to spot next time. "
                                      "If you don't recognise it, change your Wi-Fi password.",
                               "action": "Check that you recognise it",
                               "tech": "Not present in the previous scan of this network.", "details": {}})
            # e.g. ["critical", "low"]
            severities = [f["severity"] for f in issues]
            # how many problems this device has
            d["issues"] = len(issues)
            # this device's own score out of 100
            d["score"] = vi.host_score(severities)
            per_host.append(severities)
            findings += issues
        # one weird device shouldn't break the whole report
        except Exception:
            continue

    # devices that were here last time but not now
    gone = [{"ip": d.get("ip"), "device": _name(d, names), "category": d.get("category")}
            for d in prev_devices if device_key(d) not in now_keys]

    # worst problems first, then sorted by device name
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), str(f.get("device"))))
    # the network score (average of devices with problems)
    score = vi.score_hosts(per_host)
    # show 71.5 as 72, but 70.0 as 70
    score = int(score) if float(score).is_integer() else round(score)
    # e.g. 72 -> "fair"
    band = next(name for floor, name in BANDS if score >= floor)
    # how many of each
    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in SEVERITY_ORDER}

    report = {"score": score, "band": band, "counts": counts, "findings": findings,
              "gone": gone, "first_scan": first_scan,
              # when the scan we compared with was
              "compared_to": (previous or {}).get("scanned_at")}
    # save it inside the scan too
    result["report"] = report
    return report
