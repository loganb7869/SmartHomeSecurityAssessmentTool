# scanner.py - the main scanning part of our project
#
# DISCLAIMER: this uses the python-nmap library, which is just a Python wrapper
# around the nmap program from https://nmap.org/download.html. nmap has to be
# installed on the computer for any of this to work.
#
# What this file does, in order:
#     1. finds which devices on the network are turned on (nmap "-sn")
#     2. listens for devices that announce themselves (TVs, phones, routers)
#     3. looks closer at each device: open ports, what software, what OS
#     4. guesses what kind of device each one is (phone, computer, TV...)
#     5. prints everything as JSON so server.py can show it on the web page
#
# The nmap options we use:
#     -sn                   just check which devices are on, no port scan
#     -sS                   "SYN" port scan (fast, but needs sudo/admin)
#     -sT                   normal "connect" port scan (works without sudo)
#     -sV --version-light   quickly ask open ports what software they are running
#     -O --osscan-limit     guess the operating system (needs sudo/admin)
#     -p ...                our own list of ports to check (see PORTS below)
#     -Pn                   scan every device we found, even ones that ignore pings
#     --host-timeout        give up on one slow device instead of waiting forever
#     -T4                   go faster
#
# If something goes wrong we try to keep going with less info instead of
# crashing, and anything we can't fix gets printed as {"error": "..."} so the
# web page can show the user what happened.
#
# You can run it on its own too:  sudo python3 scanner.py 192.168.1.0/24
# (or just give it any IP on the network, like 192.168.1.15, and it scans that whole network)

# for checking and working with IP addresses and networks
import ipaddress
# to print our results as JSON for server.py
import json
# for file paths and checking if we're admin
import os
# to know if we're on Mac, Linux or Windows
import platform
# regular expressions, used to pull the router IP out of command output
import re
# to run the "route" command that tells us the router's IP
import subprocess
# for printing to stderr and reading command line arguments
import sys
# so we can listen for TVs/phones while other stuff runs
import threading
# for timestamps and measuring how long the scan took
import time

# python-nmap might not be installed yet
try:
    # the library that runs nmap for us
    import nmap
# if it's missing we don't crash right away...
except ImportError:
    # ...we remember it's missing and explain it later in get_scanner()
    nmap = None

# our file with the extra ways of finding devices (ARP, mDNS, SSDP)
import discovery
# our teammate's list of risky ports and how bad they are
import vulnerability_identifier as vi
# the "what kind of device is this" rules
from device_type_guesser import (explain_guess, first_hint, TYPES, PORT_HINTS,
                                 SSDP_HINTS, MDNS_HINTS, HOSTNAME_HINTS)

# Places nmap might be installed, because it's in a different spot on every OS.
# "/opt/homebrew/bin/nmap" is where Homebrew puts it on newer Macs.
NMAP_PATHS = (
    # whatever is on the PATH
    "nmap",
    # Mac (Homebrew) and Linux
    "/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/usr/bin/nmap",
    # Windows
    r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe",
)

# the network we scan if nobody tells us one (most home routers use this)
DEFAULT_NETWORK = "192.168.1.0/24"
# where DHCP.py saves device names
DHCP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dhcp_names.json")
# biggest network we allow (a /22). A /16 would take hours so we block it
MAX_ADDRESSES = 1024

# The ports we check on every device. These are everyday ones (web pages, file sharing,
# printers...) plus the ones that tell us what a device is (like 62078 = iPhone).
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 443, 445, 515,
                548, 554, 631, 993, 995, 1080, 1400, 1883, 1900, 2869, 3000, 3306, 3389,
                5000, 5001, 5353, 5357, 5900, 7000, 7100, 8000, 8008, 8009, 8060, 8080,
                8443, 8888, 9000, 9100, 10001, 49152, 49153, 49154, 62078]
# Join our list with the ports the device guesser and the vulnerability file care about,
# take out duplicates (set), sort them, and turn them into "21,22,23,..." for nmap's -p option.
PORTS = ",".join(str(p) for p in sorted(set(COMMON_PORTS) | set(PORT_HINTS) | set(vi.COMMON_PORTS)))

# step 1: just find out who's turned on
DISCOVERY_ARGS = "-sn -T4"
# best scan, needs sudo
DETAIL_ARGS_ADMIN = f"-Pn -sS -sV --version-light -O --osscan-limit -p {PORTS} -T4 --host-timeout 90s"
# works without sudo, but no OS guess
DETAIL_ARGS_USER = f"-Pn -sT -sV --version-light -p {PORTS} -T4 --host-timeout 90s"
# last resort if the other two fail
DETAIL_ARGS_SIMPLE = f"-Pn -sT -p {PORTS} -T4 --host-timeout 60s"


#
# Class: ScanError - a problem we can explain to the user in normal words (like "nmap isn't installed")
#
class ScanError(Exception):
    pass


# ---------------------------------------------------------------------------
# Little helper functions
# ---------------------------------------------------------------------------

# server.py looks for lines that start with this to update the progress bar
PROGRESS_TAG = "@@PROGRESS "


#
# Function: progress - Tell server.py how far along we are (0-100) so the web page progress bar moves.
# Input argument: pct - how far along the scan is, 0 to 100
#                 text - the message to show next to the progress bar
# Output argument: none
# Return: none
# Dependencies: json - dumps; sys - stderr
#
def progress(pct, text):
    # printing should never crash the scan
    try:
        # keep the number between 0 and 100
        pct = round(max(0, min(100, pct)))
        # e.g. @@PROGRESS {"pct": 20, "text": "..."}
        line = PROGRESS_TAG + json.dumps({"pct": pct, "text": text})
        # stderr, because stdout is saved for the final JSON
        print(line, file=sys.stderr, flush=True)
    # if printing fails for some reason...
    except Exception:
        # ...we just skip this update
        pass


#
# Function: warn - Print a warning, and also save it in the list that gets shown on the web page.
# Input argument: msg - the warning message
#                 warnings - the list of warnings shown to the user (optional)
# Output argument: warnings - the message gets added to it (if a list is given)
# Return: none
# Dependencies: sys - stderr
#
def warn(msg, warnings=None):
    # stderr again so we don't mess up the JSON on stdout
    print(f"Warning: {msg}", file=sys.stderr)
    # only some warnings are worth showing the user
    if warnings is not None:
        # those get added to the list
        warnings.append(msg)


#
# Function: is_admin - True if we're running as root (Mac/Linux, i.e. with sudo) or as Administrator (Windows).
# Input argument: none
# Output argument: none
# Return: True if we're running as admin
# Dependencies: ctypes; os - geteuid
#
def is_admin():
    try:
        # Mac and Linux have geteuid, Windows doesn't
        if hasattr(os, "geteuid"):
            # user id 0 means root
            return os.geteuid() == 0
        # Windows only: lets us call a Windows function
        import ctypes
        # asks Windows "is this user an admin?"
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    # if anything goes wrong checking...
    except Exception:
        # ...we assume we're not admin
        return False


#
# Function: get_scanner - Make a new nmap scanner object, or raise a ScanError that says what's missing.
# Input argument: none
# Output argument: none
# Return: a new nmap.PortScanner (raises ScanError if nmap is missing)
# Dependencies: nmap - PortScanner, PortScannerError; sys - executable; ScanError
#
def get_scanner():
    # python-nmap failed to import at the top
    if nmap is None:
        raise ScanError("python-nmap isn't installed. Run: "
                        f"{sys.executable} -m pip install python-nmap")
    try:
        # this fails if the nmap program itself isn't installed
        return nmap.PortScanner(nmap_search_path=NMAP_PATHS)
    # nmap program not found in any of our paths
    except nmap.PortScannerError:
        raise ScanError("The nmap program wasn't found. Install it from "
                        "https://nmap.org/download.html (Mac: brew install nmap, "
                        "Linux: sudo apt install nmap) and try again.")


#
# Function: check_network - Turn what the user typed into a network we can scan.
# Input argument: text - what the user typed (a network or a single IP)
# Output argument: none
# Return: the network to scan (raises ScanError if it isn't valid)
# Dependencies: ipaddress - ip_address, ip_network; ScanError
#
def check_network(text):
    # The user can type a whole network (192.168.1.0/24) or just ONE IP address
    # they know is on the network (like their router, 192.168.1.1, or their own
    # computer, 192.168.1.15). If there's no "/", we scan the /24 that IP is on,
    # which means everything from x.x.x.0 to x.x.x.255.
    # get rid of spaces around what they typed
    text = str(text).strip()
    # empty box
    if not text:
        raise ScanError("Type a network (like 192.168.1.0/24) or any IP address on it (like 192.168.1.1).")
    # they gave a single IP, not a network
    if "/" not in text:
        try:
            # check it's a real IP address
            ip = ipaddress.ip_address(text)
        # not an IP, e.g. "hello" or "192.168.1"
        except ValueError:
            raise ScanError(f"'{text}' isn't an IP address. Use something like 192.168.1.1 or 192.168.1.0/24")
        # /24 = the usual home network size (256 addresses)
        prefix = 24 if ip.version == 4 else 120
        # so 192.168.1.15 becomes 192.168.1.15/24
        text = f"{ip}/{prefix}"
    try:
        # strict=False lets 192.168.1.15/24 become 192.168.1.0/24
        net = ipaddress.ip_network(text, strict=False)
    # something like 192.168.1.0/99
    except ValueError:
        raise ScanError(f"'{text}' isn't a valid network. Use something like 192.168.1.0/24")
    # too many addresses to scan in a reasonable time
    if net.num_addresses > MAX_ADDRESSES:
        raise ScanError(f"{net} has {net.num_addresses:,} addresses, which would take far too long. "
                        f"Use a smaller network (at most {MAX_ADDRESSES}, like a /24).")
    # only home/school style networks
    if not (net.is_private or net.is_loopback or net.is_link_local):
        raise ScanError(f"{net} isn't a home/private network. Only scan networks you own.")
    # e.g. IPv4Network('192.168.1.0/24')
    return net


#
# Function: safe_hostname - Get the device's name from nmap without crashing if it's missing.
# Input argument: info - nmap's information about one device
# Output argument: none
# Return: the device's name, or None
# Dependencies: none
#
def safe_hostname(info):
    try:
        # nmap gives "" when there's no name, so turn that into None
        return info.hostname() or None
    # info might be None or something weird
    except Exception:
        return None


#
# Function: safe_state - Get "up" or "down" from nmap without crashing.
# Input argument: info - nmap's information about one device
# Output argument: none
# Return: "up", "down" or "unknown"
# Dependencies: none
#
def safe_state(info):
    try:
        # usually "up"
        return info.state()
    except Exception:
        # if we can't tell
        return "unknown"


#
# Function: mac_and_vendor - Find the MAC address and who made the device, from whichever scan has them.
# Input argument: *infos - nmap's info for the device from each scan pass (any number, can be None)
# Output argument: none
# Return: (MAC, maker), either can be None
# Dependencies: none
#
def mac_and_vendor(*infos):
    # start with nothing found
    mac = vendor = None
    # we pass in results from more than one scan
    for info in infos:
        # that scan didn't see this device
        if info is None:
            continue
        try:
            # keep the first MAC we find
            mac = mac or (info.get("addresses") or {}).get("mac")
            # if we have a MAC but no maker yet
            if mac and not vendor:
                # nmap stores makers by MAC
                vendor = (info.get("vendor") or {}).get(mac)
        # weird data, just try the next one
        except Exception:
            continue
    # either can still be None
    return mac, vendor


#
# Function: open_ports_of - List of open port numbers on a device, sorted. Skips anything that looks broken.
# Input argument: info - nmap's information about one device
# Output argument: none
# Return: a sorted list of open port numbers
# Dependencies: none
#
def open_ports_of(info):
    # a set so the same port isn't added twice
    ports = set()
    # no detailed scan for this device
    if info is None:
        return []
    try:
        # usually just ["tcp"]
        protocols = info.all_protocols()
    except Exception:
        return []
    # go through tcp (and udp if there is any)
    for proto in protocols:
        try:
            # every port nmap checked
            for port, details in info[proto].items():
                # only the open ones
                if isinstance(details, dict) and details.get("state") == "open":
                    # make sure it's a number
                    ports.add(int(port))
        # bad data for this protocol, skip it
        except Exception:
            continue
    # e.g. [22, 80, 443]
    return sorted(ports)


#
# Function: default_gateway - Try to find the router's IP address. Returns None if we can't tell.
# Input argument: none
# Output argument: none
# Return: the router's IP, or None
# Dependencies: ipaddress - IPv4Address; os - path.exists; platform - system; re - M, search; subprocess - run
#
def default_gateway():
    # "Darwin" = Mac, "Linux", or "Windows"
    system = platform.system()
    try:
        # Linux keeps the routing table in this file
        if system == "Linux" and os.path.exists("/proc/net/route"):
            with open("/proc/net/route") as f:
                # skip the header line
                for line in f.readlines()[1:]:
                    # columns: interface, destination, gateway, ...
                    parts = line.split()
                    # destination 0.0.0.0 = the default route
                    if len(parts) > 2 and parts[1] == "00000000":
                        # the gateway is written backwards in hex, so we flip it and turn it into an IP
                        return str(ipaddress.IPv4Address(bytes.fromhex(parts[2])[::-1]))
        # Mac
        elif system == "Darwin":
            out = subprocess.run(["route", "-n", "get", "default"], capture_output=True,
                                 # prints a line like "gateway: 192.168.1.1"
                                 text=True, timeout=3).stdout
            # grab the IP after "gateway:"
            m = re.search(r"gateway:\s*([\d.]+)", out)
            if m:
                return m.group(1)
        elif system == "Windows":
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True,
                                 # Windows routing table
                                 text=True, timeout=3).stdout
            # the line for 0.0.0.0, third column is the gateway
            m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)", out, re.M)
            if m:
                return m.group(1)
    # command missing, timed out, etc.
    except Exception:
        pass
    # couldn't figure it out
    return None


#
# Function: looks_like_router - Is this IP the router? Uses the real gateway if we know it, otherwise guesses x.x.x.1.
# Input argument: ip - an IP address as text
#                 gateway - the router's IP if we know it, otherwise None
#                 net - the network being scanned, e.g. 192.168.1.0/24
# Output argument: none
# Return: True if this IP is the router
# Dependencies: ipaddress - ip_address
#
def looks_like_router(ip, gateway, net):
    try:
        # only trust the gateway if it's on the network we scanned
        if gateway and ipaddress.ip_address(gateway) in net:
            return ip == gateway
    # gateway wasn't a proper IP
    except ValueError:
        pass
    try:
        # every usable address in the network
        hosts = net.hosts()
        # the first one, e.g. 192.168.1.1, is usually the router
        return ip == str(next(iter(hosts)))
    except Exception:
        return False


#
# Function: load_dhcp_names - Read the device names DHCP.py saved. Returns {MAC: {...}} or {} if there aren't any.
# Input argument: warnings - the list of warnings shown to the user (optional)
# Output argument: warnings - a warning gets added if the file is broken
# Return: {MAC: info}, or {} if there aren't any
# Dependencies: json - JSONDecodeError, load; warn
#
def load_dhcp_names(warnings=None):
    try:
        with open(DHCP_FILE) as f:
            data = json.load(f)
    # DHCP.py hasn't saved anything yet, that's fine
    except FileNotFoundError:
        return {}
    # file is broken or can't be read
    except (json.JSONDecodeError, OSError) as e:
        warn(f"couldn't read dhcp_names.json ({e}); skipping DHCP names", warnings)
        return {}
    # file has the wrong shape
    if not isinstance(data, dict):
        return {}
    # make every MAC uppercase so it matches the way nmap writes them
    return {str(mac).upper(): info for mac, info in data.items() if isinstance(info, dict)}


#
# Function: dhcp_lookup - Find a device's DHCP info by MAC address, or by IP if we don't know its MAC.
# Input argument: dhcp - the device names from DHCP.py, {MAC: info}
#                 mac - a MAC address as text
#                 ip - an IP address as text
# Output argument: none
# Return: the device's DHCP info, or {} if we don't have any
# Dependencies: none
#
def dhcp_lookup(dhcp, mac, ip):
    # best match: same hardware address
    if mac and mac.upper() in dhcp:
        return dhcp[mac.upper()]
    # otherwise look for the same IP
    for info in dhcp.values():
        if info.get("ip") == ip:
            return info
    # nothing found
    return {}


#
# Function: ip_sort_key - Used for sorting IPs like numbers (so .9 comes before .10, not after).
# Input argument: ip - an IP address as text
# Output argument: none
# Return: something to sort by, so IPs sort like numbers
# Dependencies: ipaddress - ip_address
#
def ip_sort_key(ip):
    try:
        # turn the IP into one big number
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        # anything that isn't an IP goes to the end
        return (1, ip)


#
# Function: save_xml - Save nmap's raw XML output to a file. If this fails the scan still carries on.
# Input argument: nm - the nmap results (an nmap scanner or a dictionary)
#                 filename - the file to read or write
# Output argument: none
# Return: none
# Dependencies: warn
#
def save_xml(nm, filename):
    try:
        # the XML nmap printed
        data = nm.get_nmap_last_output()
        # sometimes it's text instead of bytes
        if isinstance(data, str):
            # turn it into bytes so we can write it in "wb" mode
            data = data.encode()
        with open(filename, "wb") as f:
            f.write(data or b"")
    except Exception as e:
        warn(f"couldn't save {filename}: {e}")


# ---------------------------------------------------------------------------
# The two scan passes (used by both the terminal version and the web page)
# ---------------------------------------------------------------------------

#
# Function: run_discovery - Pass 1: which devices are turned on? Gives back (the nmap scanner, [list of IPs that answered]).
# Input argument: net - the network being scanned, e.g. 192.168.1.0/24
#                 warnings - the list of warnings shown to the user (optional)
# Output argument: none
# Return: (the nmap scanner, a sorted list of IPs that are on)
# Dependencies: nmap - PortScannerError; ScanError, get_scanner, ip_sort_key, safe_state
#
def run_discovery(net, warnings):
    # new nmap object
    nm = get_scanner()
    try:
        # "-sn": ping every address on the network
        nm.scan(hosts=str(net), arguments=DISCOVERY_ARGS)
    # nmap itself failed
    except nmap.PortScannerError as e:
        raise ScanError(f"nmap couldn't run the discovery scan: {str(e).strip()[:300]}")
    # keep only devices that are up
    live = [h for h in nm.all_hosts() if safe_state(nm[h]) == "up"]
    # sorted by IP so the list looks neat
    return nm, sorted(live, key=ip_sort_key)


# how many devices go into one nmap run (smaller = progress bar moves more often)
DETAIL_BATCH = 6
# how many nmap runs happen at the same time
DETAIL_WORKERS = 3


#
# Function: _scan_batch - Run nmap on a few devices. If it fails we try simpler options.
# Input argument: batch - a few IPs to scan together
#                 attempts - the nmap option sets to try, best first
#                 warnings - the list of warnings shown to the user
# Output argument: warnings - a warning gets added if every attempt fails
# Return: ({ip: nmap info}, the raw XML or None)
# Dependencies: nmap - PortScannerError; get_scanner, warn
#
def _scan_batch(batch, attempts, warnings):
    # Gives back ({ip: nmap info}, the raw XML or None).
    # best options first, simplest last
    for args in attempts:
        nm = get_scanner()
        try:
            # nmap takes a space separated list of IPs
            nm.scan(hosts=" ".join(batch), arguments=args)
            # results for every device it saw
            found = {h: nm[h] for h in nm.all_hosts()}
            try:
                # keep the XML too (main.py saves it)
                raw = nm.get_nmap_last_output()
            except Exception:
                raw = None
            # worked, so we stop here
            return found, raw
        # e.g. "-sS needs root" -> try the next, simpler options
        except nmap.PortScannerError as e:
            warn(f"detailed scan of {', '.join(batch)} with '{args.split(' -p ')[0]}' failed "
                 f"({str(e).strip()[:200]}); trying simpler options")
        # anything else unexpected, also try simpler options
        except Exception as e:
            warn(f"detailed scan of {', '.join(batch)} failed unexpectedly ({e}); trying simpler options")
    # every option failed for these devices
    warn(f"couldn't look closely at {', '.join(batch)}, so only basic information is shown", warnings)
    return {}, None


#
# Function: run_detail - Pass 2: look closer at the devices that are on, a few at a time, updating the progress bar.
# Input argument: live - the list of IPs that are turned on
#                 warnings - the list of warnings shown to the user (optional)
#                 batch_size - how many devices per nmap run (None = all at once)
#                 pct_from - where the progress bar starts for this step
#                 pct_to - where the progress bar ends for this step
# Output argument: warnings - warnings get added if something fails
# Return: ({ip: nmap info}, a list of raw XML outputs)
# Dependencies: sys - stderr; _scan_batch, is_admin, progress, warn
#
def run_detail(live, warnings, batch_size=DETAIL_BATCH, pct_from=35, pct_to=95):
    # Gives back ({ip: nmap info}, [raw XML outputs]). Devices that couldn't be
    # scanned just won't be in the dictionary.
    # lets us run a few nmaps at once
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # the list of option sets to try, best first
    attempts = []
    # with sudo we can do the full scan
    if is_admin():
        attempts.append(DETAIL_ARGS_ADMIN)
    # without sudo, tell the user what they're missing
    else:
        warn("not running as administrator/root, so there's no OS detection and "
             "makers (MAC addresses) may be missing. Run with sudo for full results.", warnings)
    # always have the simpler ones as backups
    attempts += [DETAIL_ARGS_USER, DETAIL_ARGS_SIMPLE]

    # batch_size=None means "everything in one go" (main.py uses that)
    size = batch_size or len(live) or 1
    # split the IP list into groups
    batches = [live[i:i + size] for i in range(0, len(live), size)]
    # what we found, the XML outputs, and how many devices are done
    results, raws, done = {}, [], 0
    print(f"Scanning {len(live)} device(s) in {len(batches)} group(s)", file=sys.stderr)
    progress(pct_from, f"Looking closely at {len(live)} device{'s' if len(live) != 1 else ''}")
    # start the workers
    with ThreadPoolExecutor(max_workers=min(DETAIL_WORKERS, len(batches)) or 1) as pool:
        # one job per group
        futures = {pool.submit(_scan_batch, b, attempts, warnings): b for b in batches}
        # handle each group as soon as it finishes
        for fut in as_completed(futures):
            # which IPs this job was for
            batch = futures[fut]
            try:
                # get what _scan_batch returned
                found, raw = fut.result()
            # the job crashed
            except Exception as e:
                warn(f"couldn't scan {', '.join(batch)} ({e})", warnings)
                found, raw = {}, None
            # add these devices to the results
            results.update(found)
            if raw:
                raws.append(raw)
            # count them as done
            done += len(batch)
            # move the bar between 35% and 95%
            progress(pct_from + (pct_to - pct_from) * done / len(live),
                     f"Looked closely at {done} of {len(live)} devices")
    # there were devices but nothing worked at all
    if live and not results:
        warn("the detailed scan didn't work, so only basic information is shown", warnings)
    return results, raws


# ---------------------------------------------------------------------------
# Terminal version (this is what main.py uses)
# ---------------------------------------------------------------------------

#
# Function: ask_choice - Ask the user which kind of device to show, until they type a valid answer.
# Input argument: none
# Output argument: none
# Return: the type they picked
# Dependencies: device_type_guesser.py - TYPES
#
def ask_choice():
    while True:
        try:
            choice = input("Scan for (computer, mobile, console, tv, iot, all): ").strip().lower()
        # no keyboard input (e.g. piped in), so just show everything
        except EOFError:
            return "all"
        # one of the allowed answers
        if choice in TYPES:
            return choice
        # otherwise ask again
        print("Please type one of: " + ", ".join(TYPES))


#
# Function: discover_hosts - Terminal version, step 1: find devices that are on and print them.
# Input argument: address - the network or single IP to scan
#                 choice - the device type to show (computer, mobile, console, tv, iot or all)
# Output argument: none
# Return: none
# Dependencies: ScanError, ask_choice, check_network, default_gateway, dhcp_lookup, load_dhcp_names, looks_like_router, mac_and_vendor, run_discovery, safe_hostname, save_xml, scan_hosts
#
def discover_hosts(address=DEFAULT_NETWORK, choice=None):
    try:
        # also works with just one IP
        net = check_network(address)
    except ScanError as e:
        # e.g. "isn't a valid network"
        print(e)
        return
    # tell them which network we picked from their IP
    if "/" not in str(address):
        print(f"Scanning {net} (the network {address} is on)")
    # use the type they passed in, or ask
    choice = choice or ask_choice()
    warnings = []
    try:
        nm, live = run_discovery(net, warnings)
    except ScanError as e:
        print(e)
        return
    # keep the raw results, xml_parser.py can read these
    save_xml(nm, "discovery_results.xml")

    # the router's IP if we can find it
    gateway = default_gateway()
    # names collected by DHCP.py
    dhcp = load_dhcp_names()
    # print a short block for each device
    for host in live:
        print("-------------------------")
        print("IP Address:", host)
        # name from nmap,
        print("Hostname:", safe_hostname(nm[host]) or
              # or from DHCP,
              dhcp_lookup(dhcp, mac_and_vendor(nm[host])[0], host).get("hostname") or
              # or our guess
              ("Router" if looks_like_router(host, gateway, net) else "IoT Device"))
        print("MAC Address:", mac_and_vendor(nm[host])[0] or "n/a")

    if not live:
        print("No live hosts found.")
        return

    print("-------------------------")
    # step 2
    scan_hosts(live, choice, net=net, first=nm, gateway=gateway, dhcp=dhcp)


#
# Function: scan_hosts - Terminal version, step 2: look closer at each device and print the ones that match `choice`.
# Input argument: live - the list of IPs that are turned on
#                 choice - the device type to show (computer, mobile, console, tv, iot or all)
#                 net - the network being scanned, e.g. 192.168.1.0/24
#                 first - the results of pass 1 (the discovery scan)
#                 gateway - the router's IP if we know it, otherwise None
#                 dhcp - the device names from DHCP.py, {MAC: info}
# Output argument: none
# Return: none
# Dependencies: device_type_guesser.py - explain_guess; ipaddress - ip_network; vulnerability_identifier.py - COMMON_PORTS, determine_vulnerability; dhcp_lookup, ip_sort_key, load_dhcp_names, looks_like_router, mac_and_vendor, open_ports_of, run_detail, safe_hostname, safe_state, warn
#
def scan_hosts(live, choice, net=None, first=None, gateway=None, dhcp=None):
    # fallback if called on its own
    net = net or ipaddress.ip_network(DEFAULT_NETWORK)
    dhcp = load_dhcp_names() if dhcp is None else dhcp
    # one group, so we get one XML file
    nm, raws = run_detail(live, [], batch_size=None)
    # nothing came back
    if not nm:
        print("The detailed scan failed. See the warnings above.")
        return
    # save the XML so xml_parser.py can use it later
    if raws:
        try:
            with open("scan_results.xml", "wb") as f:
                f.write(raws[0] if isinstance(raws[0], bytes) else raws[0].encode())
        except OSError as e:
            warn(f"couldn't save scan_results.xml: {e}")

    # how many devices matched what they asked for
    shown = 0
    for host in sorted(nm, key=ip_sort_key):
        # nmap's info for this device
        info = nm[host]
        first_info = first[host] if first is not None and host in first.all_hosts() else None
        mac = mac_and_vendor(info, first_info)[0]
        # DHCP info if we have it
        d = dhcp_lookup(dhcp, mac, host)
        name = safe_hostname(info) or d.get("hostname")
        # "computer", "mobile", ...
        dtype = explain_guess(nm, host, name, d.get("dhcp_class"))[0]
        # skip devices that aren't the type they asked for
        if choice != "all" and dtype != choice:
            continue
        shown += 1
        print("-------------------------")
        print("IP Address:", host)
        print("Hostname:", name or
              ("Router" if looks_like_router(host, gateway, net) else "IoT Device"))
        print("Device type:", dtype)
        print("State:", safe_state(info))
        try:
            # nmap's OS guesses, best first
            if info.get("osmatch"):
                print("OS guess:", info["osmatch"][0].get("name", "?"))
        except Exception:
            pass
        try:
            for proto in info.all_protocols():
                for port in sorted(info[proto]):
                    # details for this port
                    p = info[proto][port]
                    risk = ""
                    # is it on the risky list?
                    if p.get("state") == "open" and port in vi.COMMON_PORTS:
                        # e.g. [Risk: Critical]
                        risk = f"  [Risk: {vi.COMMON_PORTS[port]['severity']}]"
                    print(f"Port: {port:<5} State: {p.get('state', '?'):<8} Service: "
                          f"{p.get('name', '')} {p.get('product', '')} {p.get('version', '')}".rstrip() + risk)
        except Exception:
            print("(couldn't read the port list for this host)")

    print(f"\n{shown} device(s) matched '{choice}'.")

    # the overall safety score, worked out by the vulnerability file
    try:
        # the format it expects
        hosts = [{"ports": [{"port": p, "state": "open"} for p in open_ports_of(nm[h])]} for h in nm]
        print(f"Network safety score: {vi.determine_vulnerability(hosts)}/100")
    except Exception as e:
        print(f"(Couldn't work out the safety score: {e})")


# ---------------------------------------------------------------------------
# Web page version: server.py runs "scanner.py <network>" and reads the JSON we print
# ---------------------------------------------------------------------------

# the device guesser uses short names, the web page uses these names for its colors and icons
PAGE_TYPES = {
    "computer": "computer",
    "mobile": "phone",
    "phone": "phone",
    "console": "game_console",
    "game_console": "game_console",
    "tv": "tv_media",
    "media": "tv_media",
    "iot": "iot_other",
}


#
# Function: _host_from - Get one device's info out of either an nmap scanner or a plain dict. None if it's not there.
# Input argument: scanner - an nmap scanner or a dictionary of results
#                 host - one device's IP address
# Output argument: none
# Return: the device's info, or None
# Dependencies: none
#
def _host_from(scanner, host):
    try:
        # run_detail gives us a dict
        if isinstance(scanner, dict):
            return scanner.get(host)
        # run_discovery gives us an nmap scanner
        if scanner is not None and host in scanner.all_hosts():
            return scanner[host]
    except Exception:
        pass
    return None


#
# Function: describe_device - Put together everything we know about one device into the dict the web page shows.
# Input argument: host - one device's IP address as text
#                 first - the results of pass 1 (the discovery scan)
#                 detail - the results of pass 2 (the detailed scan)
#                 gateway - the router's IP if we know it, otherwise None
#                 net - the network being scanned, e.g. 192.168.1.0/24
#                 dhcp - the device names from DHCP.py, {MAC: info}
#                 extras - extra clues from discovery.py (ARP, mDNS, SSDP, this computer's IPs)
# Output argument: none
# Return: a dictionary with everything the web page shows for the device
# Dependencies: device_type_guesser.py - HOSTNAME_HINTS, MDNS_HINTS, SSDP_HINTS, explain_guess, first_hint; discovery.py - is_private_mac, own_name; _host_from, dhcp_lookup, looks_like_router, mac_and_vendor, open_ports_of, safe_hostname, services_of, warn
#
def describe_device(host, first, detail, gateway, net, dhcp=None, extras=None):
    # the ARP / mDNS / SSDP results (can be empty)
    extras = extras or {}
    # pass 2 info (ports, OS)
    detail_info = _host_from(detail, host)
    # pass 1 info (name, MAC)
    first_info = _host_from(first, host)
    # use the most detailed one we have
    info = detail_info or first_info or {}

    mac, vendor = mac_and_vendor(detail_info, first_info)
    # the ARP table knows MACs of sleeping devices too
    mac = mac or extras.get("arp", {}).get(host)
    dhcp_info = dhcp_lookup(dhcp or {}, mac, host)
    # Bonjour info (names like "Derek's iPhone")
    mdns = extras.get("mdns", {}).get(host, {})
    # UPnP info (TVs and routers announce themselves this way)
    ssdp = extras.get("ssdp", {}).get(host, "")
    # is this the computer running the scan?
    is_self = host in extras.get("self", set())
    hostname = (safe_hostname(info) or safe_hostname(first_info) or dhcp_info.get("hostname")
                # first name we can find
                or mdns.get("name") or (discovery.own_name() if is_self else None))
    # e.g. "MSFT 5.0" means Windows
    dhcp_class = dhcp_info.get("dhcp_class")
    is_router = looks_like_router(host, gateway, net)
    # phones use made-up "private" MACs
    private_mac = bool(mac) and discovery.is_private_mac(mac)

    # clues that didn't come from nmap, as (type, points, reason)
    extra = []
    if is_self:
        extra.append(("computer", 6, "this computer (the one running the scan)"))
    if private_mac:
        extra.append(("mobile", 3, "randomized MAC (a private Wi-Fi address)"))
    # does its UPnP announcement mention "Samsung TV" etc.?
    hint = first_hint(ssdp, SSDP_HINTS)
    if hint:
        extra.append((hint[0], hint[1], f"SSDP '{ssdp[:120]}'"))
    # e.g. model "iPhone15,2"
    model_hint = first_hint(mdns.get("model"), HOSTNAME_HINTS)
    if model_hint:
        extra.append((model_hint[0], model_hint[1], f"Apple model '{mdns['model']}'"))
    # every Bonjour service it advertises
    for svc in mdns.get("services", []):
        if svc in MDNS_HINTS:
            kind, pts = MDNS_HINTS[svc]
            extra.append((kind, pts, f"advertises {svc}"))

    # work out the points for each device type (same rules as the terminal version)
    if detail_info is not None:
        try:
            dtype, scores, clues = explain_guess(detail, host, hostname, dhcp_class, extra)
        except Exception as e:
            warn(f"couldn't guess the type of {host}: {e}")
            dtype, scores, clues = "unknown", {}, []
    # no detailed scan, but the other clues still work
    else:
        dtype, scores, clues = explain_guess(first, host, hostname, dhcp_class, extra)

    # same scores but with the web page's type names
    page_scores = {}
    for kind, pts in scores.items():
        cat = PAGE_TYPES.get(kind, "iot_other")
        page_scores[cat] = page_scores.get(cat, 0) + pts

    # reasons look like "+5 phone: hostname 'iPhone'" so the page can draw the point bars
    reasons = [f"+{pts} {PAGE_TYPES.get(kind, 'iot_other')}: {why}" for pts, kind, why in clues]
    # the router gets a big bonus for "smart home & other"
    if is_router:
        page_scores["iot_other"] = page_scores.get("iot_other", 0) + 6
        reasons.insert(0, "+6 iot_other: it's the network's gateway (your router)")
        hostname = hostname or "Router"
    # mention the maker even if it gave no points
    if vendor and not any("MAC vendor" in r for r in reasons):
        reasons.append(f"MAC vendor '{vendor}'")
    if hostname and not is_router and not any(r.endswith(f"hostname '{hostname}'") for r in reasons):
        reasons.append(f"hostname '{hostname}'")

    # nmap's operating system guess
    os_name, os_acc = None, None
    try:
        if info.get("osmatch"):
            # the most likely one
            best = info["osmatch"][0]
            os_name = best.get("name")
            os_acc = int(best.get("accuracy", 0) or 0)
    except Exception:
        pass
    if os_name and not any(r.endswith(f"'{os_name}'") for r in reasons):
        reasons.append(f"Looks like it runs {os_name}")

    # only ARP/mDNS saw it, nmap didn't
    if first_info is None and detail_info is None:
        reasons.append("seen recently but didn't answer the scan (it may be asleep)")

    open_ports = open_ports_of(detail_info)
    # list every open port as a clue
    for port in open_ports:
        if not any(r.endswith(f"TCP {port} open") for r in reasons):
            reasons.append(f"TCP {port} open")

    # pick the type with the most points (needs at least 3 points or it's "unknown")
    if page_scores and max(page_scores.values()) >= 3:
        category = max(page_scores, key=page_scores.get)
    else:
        category = "unknown"

    # how sure we are: (how much the winner beats the rest) x (how much evidence there is)
    if category == "unknown":
        confidence = 0.0
    else:
        top = page_scores[category]
        total = sum(page_scores.values())
        # 6+ points counts as "plenty of evidence"
        confidence = round((top / total) * min(1.0, top / 6), 2)

    if not reasons:
        reasons.append("no strong signals")
    reasons.append(f"Our guess: {category.replace('_', ' ')}")

    # everything the web page needs for this device
    return {
        "ip": host,
        "mac": mac or "",
        "vendor": vendor,
        "hostname": hostname,
        "category": category,
        "confidence": confidence,
        "scores": page_scores,
        "open_ports": open_ports,
        "os": os_name,
        "os_accuracy": os_acc,
        "is_router": is_router,
        "is_self": is_self,
        "randomized_mac": private_mac,
        "mdns_model": mdns.get("model"),
        "mdns_services": mdns.get("services", []),
        "ssdp": ssdp[:300] if ssdp else "",
        "services": services_of(detail_info),
        "reasons": reasons,
    }


#
# Function: services_of - [{port, name, product, version}] for each open port. security.py and the report use this.
# Input argument: info - nmap's information about one device
# Output argument: none
# Return: a list of {port, proto, name, product, version} for each open port
# Dependencies: none
#
def services_of(info):
    out = []
    if info is None:
        return out
    try:
        for proto in info.all_protocols():
            for port, d in info[proto].items():
                if isinstance(d, dict) and d.get("state") == "open":
                    out.append({"port": int(port), "proto": proto, "name": d.get("name") or "",
                                "product": d.get("product") or "", "version": d.get("version") or ""})
    except Exception:
        pass
    # lowest port number first
    return sorted(out, key=lambda x: x["port"])


#
# Function: scan_to_json - Scan the whole network (no questions asked) and give back the results as a dict.
# Input argument: cidr - the network or single IP the user typed
# Output argument: none
# Return: the results: {network, scanned_at, admin, warnings, devices, duration_seconds}
# Dependencies: discovery.py - arp_table, mdns_discover, own_ips, ssdp_discover; ipaddress - ip_address; sys - stderr; threading - Thread; time - strftime, time; check_network, default_gateway, describe_device, ip_sort_key, is_admin, load_dhcp_names, progress, run_detail, run_discovery, warn
#
def scan_to_json(cidr):
    # Looks like {"network", "scanned_at", "admin", "warnings", "devices": [...]}.
    # Raises ScanError with a normal-words message if the scan can't run at all.
    # also turns a single IP into its network
    net = check_network(cidr)
    # problems worth telling the user about
    warnings = []
    # so we can say how long it took
    started = time.time()

    progress(2, "Looking for devices that are turned on")
    # pass 1
    first, live = run_discovery(net, warnings)
    progress(20, f"Found {len(live)} device{'s' if len(live) != 1 else ''}; listening for TVs, phones and routers")

    # listen for devices announcing themselves. Both listeners run at the same time in threads
    extras = {"ssdp": {}, "mdns": {}, "arp": {}, "self": discovery.own_ips()}
    # UPnP (TVs, routers, Xbox)
    #
    # Function: listen_ssdp
    # Input argument: none
    # Output argument: extras (from scan_to_json) - extras["ssdp"] gets filled in
    # Return: none
    # Dependencies: discovery.py - ssdp_discover
    #
    def listen_ssdp(): extras["ssdp"] = discovery.ssdp_discover()
    # Bonjour (iPhones, Macs, Chromecasts)
    #
    # Function: listen_mdns
    # Input argument: none
    # Output argument: extras (from scan_to_json) - extras["mdns"] gets filled in
    # Return: none
    # Dependencies: discovery.py - mdns_discover
    #
    def listen_mdns(): extras["mdns"] = discovery.mdns_discover(net)
    listeners = [threading.Thread(target=listen_ssdp, daemon=True),
                 threading.Thread(target=listen_mdns, daemon=True)]
    for t in listeners:
        # start both
        t.start()
    for t in listeners:
        # wait for both (but never more than 10 seconds each)
        t.join(timeout=10)
    # read the ARP table after scanning, when it's the fullest
    extras["arp"] = discovery.arp_table(net)
    dhcp = load_dhcp_names(warnings)

    # add devices that nmap missed but something else saw (usually sleeping phones)
    extra_hosts = set(extras["arp"]) | set(extras["ssdp"]) | set(extras["mdns"])
    extra_hosts |= {i.get("ip") for i in dhcp.values() if i.get("ip")}
    for ip in extra_hosts:
        try:
            # only if it's on this network
            if ipaddress.ip_address(ip) in net and ip not in live:
                live.append(ip)
        except ValueError:
            continue
    live = sorted(set(live), key=ip_sort_key)
    print(f"nmap found {len(first.all_hosts())}, other methods added "
          f"{len(live) - len(first.all_hosts())}", file=sys.stderr)
    # the start of our results
    result = {
        "network": str(net),
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "admin": is_admin(),
        "warnings": warnings,
        "devices": [],
    }
    # nobody answered at all
    if not live:
        warn("no devices answered. Check the network address matches your Wi-Fi.", warnings)
        return result

    # pass 2
    detail, _raws = run_detail(live, warnings)
    progress(96, "Working out what each device is")
    gateway = default_gateway()
    if dhcp:
        print(f"Using {len(dhcp)} name(s) from dhcp_names.json", file=sys.stderr)

    for host in live:
        try:
            result["devices"].append(describe_device(host, first, detail, gateway, net, dhcp, extras))
        except Exception as e:
            # if one device has weird data we still want everyone else's results
            warn(f"couldn't read the results for {host} ({e})", warnings)
            result["devices"].append({"ip": host, "mac": "", "vendor": None, "hostname": None,
                                      "category": "unknown", "confidence": 0, "open_ports": [],
                                      "reasons": ["no strong signals"]})
    result["duration_seconds"] = round(time.time() - started, 1)
    progress(100, "Done")
    return result


if __name__ == "__main__":
    # server.py runs this file like: sudo python3 scanner.py 192.168.1.0/24
    # use the default if no network was given
    network = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_NETWORK
    try:
        # the only thing we print to stdout is the result
        print(json.dumps(scan_to_json(network), indent=2))
    # a problem we can explain
    except ScanError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(2)
    # Ctrl+C or the Stop button
    except KeyboardInterrupt:
        print(json.dumps({"error": "Scan was stopped."}))
        sys.exit(130)
    # something we didn't expect
    except Exception as e:
        print(json.dumps({"error": f"Unexpected problem: {type(e).__name__}: {e}"}))
        # also show the full error in the terminal for debugging
        raise
