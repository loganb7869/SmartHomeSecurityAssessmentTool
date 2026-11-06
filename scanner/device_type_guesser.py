TYPES = ("computer", "mobile", "console", "all")

def guess_type(nm, host):
    match = nm[host]["osmatch"][0] if nm[host].get("osmatch") else {}
    os_name = match.get("name", "").lower()
    osclass = match.get("osclass", [{}])[0] if match.get("osclass") else {}
    dev_type = osclass.get("type", "").lower()
    family = osclass.get("osfamily", "").lower()
    vendor = " ".join(nm[host].get("vendor", {}).values()).lower()

    if "playstation" in os_name or "sony interactive" in vendor:
        return "console"
    if dev_type == "phone" or family in ("ios", "android") or "iphone" in os_name:
        return "mobile"
    if family in ("windows", "mac os x", "linux") or dev_type == "general purpose":
        return "computer"
    return "unknown"