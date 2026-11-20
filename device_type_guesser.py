# device_type_guesser.py - guesses what kind of device something is (phone, computer, TV...)
#
# scanner.py uses it like this:
#     dtype = guess_type(nm, host)                     # just the answer, like "mobile"
#     dtype, scores, clues = explain_guess(nm, host)   # the answer + how we got it
#
# How it works: we look for clues and give points to each device type. Whichever
# type ends up with the most points wins (it needs at least 3, otherwise "unknown").
# The clues:
#     1. who made it (from the MAC address, e.g. "Apple", "Sony")
#     2. which operating system nmap thinks it runs (e.g. "Windows 10", "iOS")
#     3. which ports are open (e.g. 3389 = Remote Desktop, which only computers have)
#     4. the name it gave itself (e.g. "Johns-iPhone", from nmap, DHCP.py or Bonjour)
#     5. how it asked for its IP address (DHCP "vendor class", e.g. "MSFT 5.0" = Windows)
#     6. extra clues scanner.py finds with discovery.py (UPnP, Bonjour, private MACs)
#
# Each table below is: "word to look for": ("type it points to", how many points)
# Stronger clues get more points. If data is missing or weird we just get fewer
# clues, this file never crashes the scan.

# the answers main.py's "Scan for ...?" question accepts
TYPES = ["computer", "mobile", "console", "tv", "iot", "all"]

# a type needs at least this many points to win, otherwise we say "unknown"
MIN_POINTS = 3

# Clue 1: words in the maker's name -> points for a type
VENDOR_HINTS = {
    # PlayStation maker
    "sony interactive": ("console", 5),
    # Switch
    "nintendo": ("console", 5),
    # could be an Xbox or a Surface
    "microsoft": ("console", 2),
    # Roku streaming sticks and TVs
    "roku": ("tv", 5),
    # Vizio TVs
    "vizio": ("tv", 4),
    # LG TVs (they also make phones, so only 3)
    "lg electronics": ("tv", 3),
    # phones, but also TVs
    "samsung": ("mobile", 2),
    # Chromecast / Nest
    "google": ("tv", 2),
    # Echo, Fire TV, Ring
    "amazon": ("iot", 3),
    # iPhone or Mac, the ports decide
    "apple": ("mobile", 2),
    # Motorola phones
    "motorola": ("mobile", 3),
    # OnePlus phones
    "oneplus": ("mobile", 4),
    # Xiaomi phones
    "xiaomi": ("mobile", 3),
    # Dell laptops/desktops
    "dell": ("computer", 4),
    # HP ("Hewlett Packard") computers
    "hewlett": ("computer", 3),
    # Lenovo laptops
    "lenovo": ("computer", 3),
    # Wi-Fi cards in laptops
    "intel": ("computer", 3),
    # builds laptops for Dell, HP, Lenovo, Acer
    "compal": ("computer", 3),
    # builds laptops too
    "quanta": ("computer", 3),
    # laptop Wi-Fi cards
    "liteon": ("computer", 2),
    # laptop Wi-Fi cards
    "azurewave": ("computer", 2),
    # ASUS computers
    "asustek": ("computer", 2),
    # MSI
    "micro-star": ("computer", 3),
    # Raspberry Pi (small hobby computer, usually a gadget)
    "raspberry": ("iot", 4),
    # chip in many smart plugs and bulbs
    "espressif": ("iot", 5),
    # Tuya smart plugs and bulbs
    "tuya": ("iot", 5),
    # TP-Link makes routers and smart plugs
    "tp-link": ("iot", 2),
    # routers / extenders
    "netgear": ("iot", 3),
    # cable modem / router
    "ubee": ("iot", 4),
    # internet company modems
    "technicolor": ("iot", 4),
    # internet company modems
    "sagemcom": ("iot", 4),
    # eero Wi-Fi systems
    "eero": ("iot", 4),
    # Hisense TVs
    "hisense": ("tv", 4),
    # TCL TVs
    "tcl": ("tv", 4),
    # Ubiquiti Wi-Fi gear
    "ubiquiti": ("iot", 3),
    # Cisco network gear
    "cisco": ("iot", 3),
    # cable modems
    "arris": ("iot", 3),
    # Philips Hue lights
    "philips": ("iot", 3),
    # Ring doorbells/cameras
    "ring": ("iot", 3),
    # ecobee thermostats
    "ecobee": ("iot", 5),
    # Sonos speakers
    "sonos": ("tv", 3),
}

# Clue 2: words in nmap's operating system guess -> points for a type
# (Checked in order; more specific words come first.)
OS_HINTS = {
    # router software, NOT an iPhone
    "cisco ios": ("iot", 3),
    # Windows
    "windows": ("computer", 4),
    # older Macs
    "mac os": ("computer", 4),
    # newer Macs
    "macos": ("computer", 4),
    # iPhone/iPad ("cisco ios" was caught above)
    "ios": ("mobile", 4),
    # Android phones
    "android": ("mobile", 4),
    # PlayStation
    "playstation": ("console", 6),
    # Xbox
    "xbox": ("console", 6),
    # Nintendo
    "nintendo": ("console", 6),
    # Samsung TVs
    "tizen": ("tv", 4),
    # LG TVs
    "webos": ("tv", 4),
    # Roku
    "roku": ("tv", 5),
    # router software (it's Linux, but not a PC)
    "dd-wrt": ("iot", 4),
    # router software
    "openwrt": ("iot", 4),
    # router software
    "tomato": ("iot", 3),
    # MikroTik router software
    "routeros": ("iot", 4),
    # small built-in systems
    "embedded": ("iot", 2),
    # anything nmap calls a router
    "router": ("iot", 3),
    # printers
    "printer": ("iot", 3),
    # also routers and gadgets, so only 1 point
    "linux": ("computer", 1),
}

# Clue 3: open ports -> points for a type
PORT_HINTS = {
    # Remote Desktop
    3389: ("computer", 4),
    # Windows file sharing
    445: ("computer", 3),
    # Windows file sharing (older)
    139: ("computer", 2),
    # Windows RPC
    135: ("computer", 2),
    # Remote login
    22: ("computer", 1),
    # Screen sharing
    5900: ("computer", 2),
    # MySQL database (developer machines)
    3306: ("computer", 2),
    # AirPlay receiver on Macs / dev servers
    5000: ("computer", 1),
    # iPhone / iPad syncing
    62078: ("mobile", 5),
    # Android debugging
    5555: ("mobile", 3),
    # PlayStation Remote Play
    9295: ("console", 5),
    # Xbox online play
    3074: ("console", 4),
    # Chromecast
    8008: ("tv", 3),
    # Chromecast
    8009: ("tv", 3),
    # Roku
    8060: ("tv", 5),
    # AirPlay (Apple TV, smart speakers)
    7000: ("tv", 2),
    # MQTT, used by smart home gadgets
    1883: ("iot", 4),
    # Printer
    9100: ("iot", 3),
    # Printer
    631: ("iot", 2),
    # DNS, usually the router
    53: ("iot", 2),
    # Samsung TV remote control
    8001: ("tv", 5),
    # Samsung TV remote control (secure)
    8002: ("tv", 5),
    # Samsung TV screen mirroring
    9197: ("tv", 4),
    # Samsung TV
    7676: ("tv", 3),
    # Samsung TV
    9080: ("tv", 3),
    # older Samsung TVs
    55000: ("tv", 4),
    # Philips TV
    1925: ("tv", 4),
    # Philips TV
    1926: ("tv", 4),
    # LG webOS TV (also dev servers, so 1 point)
    3000: ("tv", 1),
    # LG webOS TV
    3001: ("tv", 3),
    # LG TV
    36866: ("tv", 3),
}

# Clue 4: words in the device's own name -> points for a type
# (Checked in order; first match only.)
HOSTNAME_HINTS = {
    "iphone": ("mobile", 6),
    "ipad": ("mobile", 5),
    # Samsung Galaxy phones
    "galaxy": ("mobile", 4),
    # Google Pixel phones
    "pixel": ("mobile", 4),
    "android": ("mobile", 4),
    # anything with "phone" in the name
    "phone": ("mobile", 3),
    "macbook": ("computer", 6),
    "imac": ("computer", 6),
    "mac-mini": ("computer", 6),
    # incl. default Windows names, e.g. DESKTOP-4F2K9
    "desktop": ("computer", 5),
    "laptop": ("computer", 5),
    # Lenovo laptops
    "thinkpad": ("computer", 5),
    # e.g. "Diego-PC"
    "-pc": ("computer", 4),
    "pc-": ("computer", 4),
    # PlayStation 5
    "ps5": ("console", 6),
    # PlayStation 4
    "ps4": ("console", 6),
    "playstation": ("console", 6),
    "xbox": ("console", 6),
    "nintendo": ("console", 6),
    # Nintendo Switch ("switch" could mean other things, so only 3)
    "switch": ("console", 3),
    "roku": ("tv", 6),
    "chromecast": ("tv", 6),
    "appletv": ("tv", 6),
    "apple-tv": ("tv", 6),
    # Amazon Fire TV
    "firetv": ("tv", 5),
    # e.g. "Living-Room-TV"
    "-tv": ("tv", 3),
    # Samsung TVs name themselves "[TV] Samsung ..."
    "[tv]": ("tv", 5),
    "samsung tv": ("tv", 5),
    "smart tv": ("tv", 5),
    # Sony TVs
    "bravia": ("tv", 5),
    # Amazon Echo
    "echo": ("iot", 4),
    "alexa": ("iot", 4),
    # Google Nest
    "nest": ("iot", 4),
    "ring": ("iot", 3),
    # ESP8266/ESP32 gadgets
    "esp_": ("iot", 5),
    # ESP chip gadgets
    "esp-": ("iot", 5),
    "printer": ("iot", 4),
}

# Clue 5: DHCP vendor class (what software asked for an address)
DHCP_CLASS_HINTS = {
    # Android phones say "android-dhcp-..."
    "android": ("mobile", 4),
    # Windows
    "msft": ("computer", 3),
}


# Clue 6a: UPnP/SSDP announcements (SERVER / ST text). First match only.
SSDP_HINTS = {
    "xbox": ("console", 5),
    "playstation": ("console", 5),
    "roku": ("tv", 5),
    # Samsung TV software
    "tizen": ("tv", 5),
    # LG TV software
    "webos": ("tv", 5),
    # Samsung TVs
    "remotecontrolreceiver": ("tv", 5),
    # Samsung TVs
    "samsung upnp sdk": ("tv", 4),
    # "cast to TV" support (TVs, Chromecast, Fire TV)
    "dial-multiscreen": ("tv", 4),
    # router
    "internetgatewaydevice": ("iot", 4),
    # router (it can open ports)
    "wanipconnection": ("iot", 4),
    # Windows PCs
    "windows": ("computer", 3),
    # plays media (TVs, speakers, some PCs)
    "mediarenderer": ("tv", 2),
}

# Clue 6b: Bonjour/mDNS services a device advertises (each one counts)
MDNS_HINTS = {
    # iPhone/iPad sync
    "_apple-mobdev2._tcp": ("mobile", 5),
    # Apple devices (also Macs)
    "_companion-link._tcp": ("mobile", 1),
    # Chromecast / Google TV
    "_googlecast._tcp": ("tv", 5),
    # Android TV
    "_androidtvremote2._tcp": ("tv", 5),
    # Fire TV
    "_amzn-wplay._tcp": ("tv", 4),
    # TVs, Apple TV, speakers (and Macs)
    "_airplay._tcp": ("tv", 2),
    # speakers that play Spotify
    "_spotify-connect._tcp": ("tv", 1),
    # HomeKit accessory
    "_hap._tcp": ("iot", 5),
    # printer
    "_ipp._tcp": ("iot", 4),
    # printer
    "_printer._tcp": ("iot", 4),
    # Windows-style file sharing
    "_smb._tcp": ("computer", 3),
    # Mac file sharing
    "_afpovertcp._tcp": ("computer", 3),
    # screen sharing
    "_rfb._tcp": ("computer", 3),
    # remote login
    "_ssh._tcp": ("computer", 1),
}


#
# Function: first_hint - (kind, points) for the first word of `table` found in `text`, else None.
# Input argument: text - the text to search in
#                 table - one of the hint tables, {word: (type, points)}
# Output argument: none
# Return: (type, points) for the first word found, or None
# Dependencies: none
#
def first_hint(text, table):
    low = str(text or "").lower()
    for word, hint in table.items():
        if word in low:
            return hint
    return None


#
# Function: _host_info - Get nmap's info for one device, or None if nmap doesn't have it.
# Input argument: nm - the nmap results (an nmap scanner or a dictionary)
#                 host - one device's IP address as text
# Output argument: none
# Return: nmap's info for the device, or None
# Dependencies: none
#
def _host_info(nm, host):
    try:
        # works for both an nmap scanner and a plain dict
        return nm[host]
    # not there
    except Exception:
        return None


#
# Function: _open_ports - List of (port number, details) for every open port. Skips anything that looks broken.
# Input argument: info - nmap's information about one device
# Output argument: none
# Return: a list of (port number, details) for every open port
# Dependencies: none
#
def _open_ports(info):
    found = []
    try:
        # usually ["tcp"]
        protocols = info.all_protocols()
    # no port info at all
    except Exception:
        return found
    for proto in protocols:
        try:
            # {22: {...}, 80: {...}}
            ports = info[proto]
        except Exception:
            continue
        # wrong shape, skip it
        if not isinstance(ports, dict):
            continue
        for port, details in ports.items():
            try:
                # make sure it's a number
                port = int(port)
            except (TypeError, ValueError):
                continue
            # only open ports count
            if isinstance(details, dict) and details.get("state") == "open":
                found.append((port, details))
    return found


#
# Function: explain_guess - Work out the device type and show our work.
# Input argument: nm - the nmap results (an nmap scanner or a dictionary)
#                 host - one device's IP address as text
#                 hostname - the name the device gave itself (optional)
#                 dhcp_class - how it asked for its IP, e.g. "MSFT 5.0" (optional)
#                 extra - more clues as (type, points, reason) (optional)
# Output argument: none
# Return: (type, scores, clues): the winning type, the points for each type, and every clue that gave points
# Dependencies: _host_info, _open_ports
#
def explain_guess(nm, host, hostname=None, dhcp_class=None, extra=None):
    # hostname and dhcp_class are optional extra clues (from DHCP.py or Bonjour).
    # extra is an optional list of (type, points, "reason") clues scanner.py found itself.
    #
    # Gives back (type, scores, clues):
    #   type   = "computer", "mobile", "console", "tv", "iot" or "unknown"
    #   scores = {"computer": 7, "mobile": 2, ...}  points for each type
    #   clues  = [(points, type, "reason"), ...]     every clue that gave points
    # an empty dict if nmap has nothing, so .get() still works below
    info = _host_info(nm, host) or {}
    scores, clues = {}, []

    #
    # Function: add - Give `points` to `kind` and remember why.
    # Input argument: kind - the device type getting the points
    #                 points - how many points to give
    #                 why - the reason, shown on the web page
    # Output argument: scores and clues (from explain_guess) - the points and the reason get added
    # Return: none
    # Dependencies: none
    #
    def add(kind, points, why):
        scores[kind] = scores.get(kind, 0) + points
        clues.append((points, kind, why))

    # clues scanner.py already found
    for kind, points, why in (extra or []):
        add(kind, points, why)

    # Clue 1: who made it
    try:
        # the device's MAC address
        mac = (info.get("addresses") or {}).get("mac")
        # nmap looks up the maker from the MAC
        vendor = (info.get("vendor") or {}).get(mac) if mac else None
    except Exception:
        vendor = None
    if vendor:
        # lowercase so "Apple" matches "apple"
        low = str(vendor).lower()
        for word, (kind, points) in VENDOR_HINTS.items():
            if word in low:
                add(kind, points, f"MAC vendor '{vendor}'")
                # only count one match per clue, so we don't double count
                break

    # Clue 2: the operating system (only nmap's best guess)
    try:
        # list of guesses, best first
        osmatch = info.get("osmatch") or []
        if not isinstance(osmatch, list):
            osmatch = []
        os_name = str(osmatch[0].get("name", "")) if osmatch else ""
    except Exception:
        os_name = ""
    if os_name:
        low = os_name.lower()
        # OS_HINTS is in order, more specific words first
        for word, (kind, points) in OS_HINTS.items():
            if word in low:
                add(kind, points, f"OS guess '{os_name}'")
                break

    # Clue 3: open ports (every matching port counts)
    for port, _details in _open_ports(info):
        if port in PORT_HINTS:
            kind, points = PORT_HINTS[port]
            add(kind, points, f"TCP {port} open")

    # Clue 4: the name it gave itself
    if hostname:
        low = str(hostname).lower()
        for word, (kind, points) in HOSTNAME_HINTS.items():
            if word in low:
                add(kind, points, f"hostname '{hostname}'")
                break

    # Clue 5: how it asked for its IP (DHCP vendor class)
    if dhcp_class:
        low = str(dhcp_class).lower()
        for word, (kind, points) in DHCP_CLASS_HINTS.items():
            if word in low:
                add(kind, points, f"DHCP class '{dhcp_class}'")
                break

    # not enough clues to say anything
    if not scores or max(scores.values()) < MIN_POINTS:
        return "unknown", scores, clues
    # the type with the most points
    return max(scores, key=scores.get), scores, clues


#
# Function: guess_type - Just the answer: "computer", "mobile", "console", "tv", "iot" or "unknown".
# Input argument: nm - the nmap results (an nmap scanner or a dictionary)
#                 host - one device's IP address as text
#                 hostname - the name the device gave itself (optional)
#                 dhcp_class - how it asked for its IP, e.g. "MSFT 5.0" (optional)
#                 extra - more clues as (type, points, reason) (optional)
# Output argument: none
# Return: the type: "computer", "mobile", "console", "tv", "iot" or "unknown"
# Dependencies: explain_guess
#
def guess_type(nm, host, hostname=None, dhcp_class=None, extra=None):
    # [0] = only the type, not the scores and clues
    return explain_guess(nm, host, hostname, dhcp_class, extra)[0]
