# discovery.py - extra ways to find devices that nmap misses
#
# nmap is great but phones sleep and ignore it, and it can't tell a Samsung TV
# from a laptop very well. So we added these:
#
#     arp_table(net)     devices this computer talked to recently (finds sleeping phones)
#     ssdp_discover()    devices that announce themselves with UPnP (TVs, routers, Xbox)
#     mdns_discover()    devices that announce themselves with Bonjour (iPhones, Macs,
#                        Chromecasts, printers, smart home stuff), often with their name
#     own_ips()          this computer's own IP addresses
#     own_name()         this computer's name
#
# None of these need extra packages (just what comes with Python), and none of
# them crash: if something doesn't work on a computer they just give back nothing.

# checking if an IP is inside our network
import ipaddress
# Windows uses a different arp command
import platform
# pulling IPs and MACs out of text
import re
# sending and receiving network packets
import socket
# packing/unpacking the raw bytes of mDNS packets
import struct
# running the "arp" command
import subprocess
# for the listening timeouts
import time

# ---------------------------------------------------------------------------
# ARP table: the computer's list of "IP -> MAC" for devices it heard from lately
# ---------------------------------------------------------------------------

#
# Function: normalize_mac - Make every MAC look the same: '0:1b:a:...' or '00-1B-0A-...' becomes '00:1B:0A:...'. None if it isn't a MAC.
# Input argument: mac - a MAC address as text
# Output argument: none
# Return: the MAC like "00:1B:0A:0C:0D:0E", or None if it isn't a MAC
# Dependencies: re - split
#
def normalize_mac(mac):
    # split on : or - (Windows uses -)
    parts = re.split(r"[:-]", str(mac).strip())
    # a MAC always has 6 parts
    if len(parts) != 6:
        return None
    try:
        # each part as 2 uppercase hex digits (Mac shows "1b" as "1b" but "0a" as "a")
        return ":".join(f"{int(p, 16):02X}" for p in parts)
    # a part wasn't hex
    except ValueError:
        return None


#
# Function: arp_table - {ip: MAC} for every address in `net` this computer has talked to recently.
# Input argument: net - the network being scanned, e.g. 192.168.1.0/24
# Output argument: none
# Return: {ip: MAC} for the devices on our network
# Dependencies: ipaddress - ip_address; platform - system; re - search; subprocess - run; normalize_mac
#
def arp_table(net):
    found = {}
    try:
        # -n = don't look up names (faster)
        cmd = ["arp", "-a"] if platform.system() == "Windows" else ["arp", "-an"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    # arp isn't installed or took too long
    except Exception:
        out = ""
    if not out:
        # Linux without the arp tool keeps the same info in this file
        try:
            with open("/proc/net/arp") as f:
                # turn each line into the same "(ip) at mac" shape the arp command uses
                out = "\n".join(f"({l.split()[0]}) at {l.split()[3]}" for l in f.readlines()[1:])
        except Exception:
            return found
    for line in out.splitlines():
        # find an IP (maybe in brackets), then maybe the word "at", then a MAC with : or -
        m = re.search(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", line)
        # lines like "(incomplete)" have no MAC
        if not m:
            continue
        ip, mac = m.group(1), normalize_mac(m.group(2))
        # skip broadcast (FF:FF...), empty (00:00...) and multicast (01:00:5E...) entries, they aren't real devices
        if not mac or mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or mac.startswith("01:00:5E"):
            continue
        try:
            addr = ipaddress.ip_address(ip)
            # only real devices on our network
            if addr in net and addr not in (net.network_address, net.broadcast_address):
                found[ip] = mac
        except ValueError:
            continue
    return found


#
# Function: is_private_mac - True for "private Wi-Fi addresses" (made-up MACs that iPhones and Androids use by default).
# Input argument: mac - a MAC address as text
# Output argument: none
# Return: True if it's a made-up (private) MAC
# Dependencies: normalize_mac
#
def is_private_mac(mac):
    # The second-lowest bit of the first byte is the "locally administered" bit.
    # Real hardware MACs have it set to 0, made-up ones have it set to 1.
    mac = normalize_mac(mac)
    # & 0x02 checks just that one bit
    return bool(mac) and bool(int(mac[:2], 16) & 0x02)


# ---------------------------------------------------------------------------
# SSDP / UPnP: we shout "who's out there?" and TVs, routers, Xboxes and Windows PCs answer
# ---------------------------------------------------------------------------

#
# Function: ssdp_discover - {ip: "what it said about itself"} for every device that answered.
# Input argument: timeout - how many seconds to listen for answers
# Output argument: none
# Return: {ip: what the device said about itself}
# Dependencies: socket - AF_INET, IPPROTO_IP, IPPROTO_UDP, IP_MULTICAST_TTL, SOCK_DGRAM, socket, timeout; time - time
#
def ssdp_discover(timeout=3.0):
    found = {}
    # the standard UPnP "search for everything" message
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    try:
        # a UDP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        # don't let it leave the home network
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        # check the clock every 0.3s instead of waiting forever
        s.settimeout(0.3)
        # send it twice because UDP packets can get lost
        for _ in range(2):
            # the address every UPnP device listens on
            s.sendto(msg, ("239.255.255.250", 1900))
    # no network, or not allowed
    except OSError:
        return found
    # listen for answers for 3 seconds
    end = time.time() + timeout
    while time.time() < end:
        try:
            # wait for one answer
            data, (ip, _) = s.recvfrom(4096)
        # nothing yet, keep waiting
        except socket.timeout:
            continue
        except OSError:
            break
        text = data.decode(errors="ignore")
        bits = []
        # the answer is like HTTP: "Header: value" lines
        for line in text.split("\r\n"):
            key, _, val = line.partition(":")
            # the lines that say what the device is
            if key.strip().upper() in ("SERVER", "ST", "USN") and val.strip():
                bits.append(val.strip())
        if bits:
            # a device can answer more than once
            old = found.get(ip, "")
            # only add things we haven't seen yet
            new = [b for b in bits if b not in old]
            # keep it under 600 characters
            found[ip] = (old + " | " + " | ".join(new)).strip(" |")[:600]
    s.close()
    return found


# ---------------------------------------------------------------------------
# mDNS / Bonjour: we ask which services are around, and the answers often include the device's name
# ---------------------------------------------------------------------------

# the Bonjour services we ask about (each one hints at a kind of device)
MDNS_SERVICES = [
    # Apple devices
    "_apple-mobdev2._tcp", "_companion-link._tcp", "_rdlink._tcp", "_airplay._tcp",
    # speakers and TVs
    "_raop._tcp", "_googlecast._tcp", "_androidtvremote2._tcp", "_amzn-wplay._tcp",
    # Spotify, HomeKit, printers
    "_spotify-connect._tcp", "_hap._tcp", "_ipp._tcp", "_printer._tcp",
    # computers + model info
    "_smb._tcp", "_afpovertcp._tcp", "_ssh._tcp", "_rfb._tcp", "_device-info._tcp",
]


#
# Function: _encode_name - Turn "_hap._tcp.local" into DNS format: each part with its length in front, then a 0 byte.
# Input argument: name - a name like "_hap._tcp.local"
# Output argument: none
# Return: the name as DNS bytes
# Dependencies: none
#
def _encode_name(name):
    out = b""
    # "_hap", "_tcp", "local"
    for label in name.strip(".").split("."):
        raw = label.encode()
        # e.g. b"\x04_hap"
        out += bytes([len(raw)]) + raw
    # 0 = end of the name
    return out + b"\x00"


#
# Function: _read_name - Read a DNS name out of a packet. Gives back (name, where the name ends).
# Input argument: data - the raw bytes of the packet
#                 pos - where in the packet to start reading
#                 depth - how many pointers we've followed so far (stops endless loops)
# Output argument: none
# Return: (the name, the position right after it)
# Dependencies: none
#
def _read_name(data, pos, depth=0):
    # DNS packets "compress" names: instead of repeating "local" over and over
    # they put a pointer to where it was written before. That's what the 0xC0 part handles.
    labels, jumped, end = [], False, pos
    # stop after 20 jumps in case a bad packet loops forever
    while depth < 20:
        if pos >= len(data):
            raise ValueError("name runs past end")
        # length of the next part
        length = data[pos]
        # end of the name
        if length == 0:
            pos += 1
            break
        # the top two bits set = this is a pointer, not a part
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("bad pointer")
            # the other 14 bits are where to jump to
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                # the name ends after the pointer (2 bytes)
                end = pos + 2
            jumped, pos, depth = True, ptr, depth + 1
            continue
        # read this part
        labels.append(data[pos + 1:pos + 1 + length].decode("utf-8", errors="ignore"))
        pos += 1 + length
    return ".".join(labels), (end if jumped else pos)


#
# Function: _parse_mdns - Read one mDNS answer. Gives back (services, names, IPv4 addresses, model).
# Input argument: data - the raw bytes of one mDNS answer
# Output argument: none
# Return: (services, names, IPv4 addresses, model) found in the answer
# Dependencies: socket - inet_ntoa; struct - unpack; _read_name
#
def _parse_mdns(data):
    services, names, ips, model = set(), set(), set(), None
    # header: 6 numbers, how many of each section
    _id, _flags, qd, an, ns, ar = struct.unpack("!6H", data[:12])
    # the header is 12 bytes
    pos = 12
    # skip the questions
    for _ in range(qd):
        _, pos = _read_name(data, pos)
        # type + class
        pos += 4
    # go through every answer record
    for _ in range(an + ns + ar):
        name, pos = _read_name(data, pos)
        # record type and data length
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        # where the record's data is, then skip past it
        rdata_pos, pos = pos, pos + rdlen
        low = name.lower()
        for svc in MDNS_SERVICES:
            # this record is about one of our services
            if low.endswith(svc + ".local"):
                services.add(svc)
                # "Derek's iPhone._companion-link._tcp.local" -> "Derek's iPhone"
                if rtype in (16, 33) or low != svc + ".local":
                    inst = name[: -len(svc + ".local") - 1]
                    if inst and svc != "_device-info._tcp":
                        # some names look like "aa:bb@Name", keep the part after @
                        names.add(inst.split("@")[-1])
        # PTR record: points from a service to a device's name
        if rtype == 12:
            target, _ = _read_name(data, rdata_pos)
            for svc in MDNS_SERVICES:
                if target.lower().endswith(svc + ".local"):
                    services.add(svc)
                    inst = target[: -len(svc + ".local") - 1]
                    if inst and svc != "_device-info._tcp":
                        names.add(inst.split("@")[-1])
        # A record: an IPv4 address (4 bytes)
        elif rtype == 1 and rdlen == 4:
            ips.add(socket.inet_ntoa(data[rdata_pos:rdata_pos + 4]))
        # TXT record with "model=..." in it
        elif rtype == 16 and low.endswith("_device-info._tcp.local"):
            txt, i = data[rdata_pos:rdata_pos + rdlen], 0
            # TXT is a list of strings, each with its length first
            while i < len(txt):
                ln = txt[i]
                entry = txt[i + 1:i + 1 + ln].decode(errors="ignore")
                if entry.lower().startswith("model="):
                    # e.g. "iPhone15,2"
                    model = entry[6:]
                i += 1 + ln
    # that one is just for the model, not a real service
    services.discard("_device-info._tcp")
    return services, names, ips, model


#
# Function: mdns_discover - {ip: {"services": [...], "name": "...", "model": "..."}} for every device that answered.
# Input argument: net - the network being scanned, e.g. 192.168.1.0/24
#                 timeout - how many seconds to listen for answers
# Output argument: none
# Return: {ip: {"services": [...], "name": ..., "model": ...}}
# Dependencies: socket - AF_INET, IPPROTO_IP, IPPROTO_UDP, IP_MULTICAST_TTL, SOCK_DGRAM, socket, timeout; struct - pack; time - time; _encode_name, _in, _parse_mdns
#
def mdns_discover(net, timeout=3.0):
    found = {}
    # one question packet that asks about every service at once. We send it from a normal port
    # (a "legacy" query), which makes devices answer us directly instead of everyone
    # type 12 (PTR), class 1 (internet)
    questions = b"".join(_encode_name(svc + ".local") + struct.pack("!HH", 12, 1)
                         for svc in MDNS_SERVICES)
    # header + questions
    packet = struct.pack("!6H", 0, 0, len(MDNS_SERVICES), 0, 0, 0) + questions
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        s.settimeout(0.3)
        # send twice in case one gets lost
        for _ in range(2):
            # the address and port Bonjour uses
            s.sendto(packet, ("224.0.0.251", 5353))
    except OSError:
        return found
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, (src, _) = s.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            services, names, ips, model = _parse_mdns(data)
        # broken packet, skip it
        except Exception:
            continue
        # an Apple TV or HomePod can answer FOR a sleeping iPhone, so if the answer
        # has one address on our network inside it, we trust that over who sent it
        inside = [ip for ip in ips if _in(ip, net)]
        ip = inside[0] if len(inside) == 1 else src
        # not on the network we're scanning
        if not _in(ip, net):
            continue
        entry = found.setdefault(ip, {"services": [], "name": None, "model": None})
        # add the new services
        entry["services"] = sorted(set(entry["services"]) | services)
        if names and not entry["name"]:
            # the shortest name is usually the cleanest
            entry["name"] = sorted(names, key=len)[0][:64]
        if model:
            entry["model"] = model[:64]
    s.close()
    return found


#
# Function: _in - Is this IP inside the network? (False if it's not even an IP)
# Input argument: ip - an IP address as text
#                 net - the network being scanned, e.g. 192.168.1.0/24
# Output argument: none
# Return: True if the IP is inside the network
# Dependencies: ipaddress - ip_address
#
def _in(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# This computer
# ---------------------------------------------------------------------------

#
# Function: own_ips - This computer's IPv4 addresses.
# Input argument: none
# Output argument: none
# Return: a set of this computer's IPv4 addresses
# Dependencies: socket - AF_INET, SOCK_DGRAM, getaddrinfo, gethostname, socket
#
def own_ips():
    # Trick: "connecting" a UDP socket doesn't actually send anything, but it makes
    # the computer pick which of its addresses it would use, which we can then read.
    ips = set()
    # a few different networks to cover different setups
    for target in ("192.168.1.1", "10.255.255.255", "8.8.8.8"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # no packet is sent
            s.connect((target, 9))
            # our address on the way there
            ips.add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    try:
        # also ask by computer name
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    # not a real address
    ips.discard("0.0.0.0")
    return ips


#
# Function: own_name - This computer's name, like "Dereks-MacBook-Pro" (without ".local").
# Input argument: none
# Output argument: none
# Return: this computer's name, or None
# Dependencies: socket - gethostname
#
def own_name():
    try:
        return socket.gethostname().split(".")[0] or None
    except Exception:
        return None
