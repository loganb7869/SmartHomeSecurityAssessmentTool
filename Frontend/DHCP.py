# DHCP.py - listens for devices joining the Wi-Fi and saves their names
#
# When a phone or laptop connects to Wi-Fi, it asks the router for an IP address
# using DHCP. That request usually has the device's name in it, like "Dereks-iPhone".
# We listen for those requests (no extra packages like scapy needed) and save
# the MAC, IP and name to dhcp_names.json in this folder.
#
# server.py starts this by itself in the background, so you don't need to run it.
# If you want to run it on its own:
#
#     sudo python3 DHCP.py
#
# Then turn Wi-Fi off and on (or restart) the devices you want names for.
# scanner.py reads dhcp_names.json every scan, so the names show up on the dashboard.
#
# Note: it needs sudo because port 67 (the DHCP port) is below 1024, and only
# admin can listen on those ports.

# saving the names
import json
# os.replace for safe saving
import os
# listening on the network
import socket
# printing errors, exiting
import sys
# file paths
from pathlib import Path

# the folder this file is in
HERE = Path(__file__).resolve().parent
# where we save the names (scanner.py reads it from here)
OUT_FILE = HERE / "dhcp_names.json"
# every DHCP packet has these 4 bytes at position 236 (the "magic cookie")
DHCP_MAGIC = b"\x63\x82\x53\x63"


#
# Function: load_existing - Load the names we saved before, so restarting doesn't lose them.
# Input argument: none
# Output argument: none
# Return: the saved names as {MAC: info}, or {} if there aren't any
# Dependencies: json - JSONDecodeError, load
#
def load_existing():
    try:
        with open(OUT_FILE) as f:
            data = json.load(f)
        # it should be a dict of MAC -> info
        return data if isinstance(data, dict) else {}
    # no file yet, or it's broken
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


#
# Function: save - Save to a temp file first and then swap it in, so scanner.py never reads half a file.
# Input argument: devices - every device we know about, {MAC: info}
# Output argument: none
# Return: none
# Dependencies: json - dump; os - replace; sys - stderr
#
def save(devices):
    tmp = OUT_FILE.with_suffix(".tmp")
    try:
        with open(tmp, "w") as f:
            json.dump(devices, f, indent=2)
        # the swap happens all at once
        os.replace(tmp, OUT_FILE)
    except OSError as e:
        print(f"Warning: couldn't save {OUT_FILE.name}: {e}", file=sys.stderr)


#
# Function: clean_text - Names in DHCP packets can have empty bytes or junk at the end. Keep only the readable part (max 64 characters).
# Input argument: raw - the bytes from the packet
# Output argument: none
# Return: the readable text (at most 64 characters)
# Dependencies: none
#
def clean_text(raw):
    # bytes -> text, remove empty bytes and spaces
    text = raw.decode("utf-8", errors="ignore").strip("\x00").strip()
    # remove invisible characters
    return "".join(ch for ch in text if ch.isprintable())[:64]


#
# Function: parse_packet - Read one DHCP packet. Gives back (MAC, {"ip", "hostname", "dhcp_class"}) or None if it isn't one we can use.
# Input argument: data - the raw bytes of one packet
# Output argument: none
# Return: (MAC, info) for a DHCP request, or None if it isn't one we can use
# Dependencies: socket - inet_ntoa; clean_text
#
def parse_packet(data):
    # A DHCP packet has a fixed part (240 bytes) and then a list of "options",
    # each written as: option number, length, value.
    if len(data) < 240 or data[236:240] != DHCP_MAGIC:
        # too short or no magic cookie = not DHCP
        return None
    if data[0] != 1:
        # 1 = a request from a device. 2 would be the router's reply, we skip those
        return None
    # length of the hardware address
    hlen = data[2]
    if hlen != 6:
        # normal Wi-Fi/Ethernet MACs are 6 bytes
        return None
    # bytes 28-33 are the MAC. Uppercase like nmap uses
    mac = ":".join(f"{b:02X}" for b in data[28:34])

    info = {}
    # "client IP address" (filled in when a device renews the IP it already has)
    ciaddr = data[12:16]
    if ciaddr != b"\x00\x00\x00\x00":
        # 4 bytes -> "192.168.1.5"
        info["ip"] = socket.inet_ntoa(ciaddr)

    # the options start right after the magic cookie
    i = 240
    while i < len(data):
        # which option this is
        code = data[i]
        # 255 = end of the options
        if code == 255:
            break
        # 0 = padding, it has no length
        if code == 0:
            i += 1
            continue
        # packet was cut off
        if i + 1 >= len(data):
            break
        # how long the value is
        length = data[i + 1]
        # the value itself
        val = data[i + 2:i + 2 + length]
        # packet was cut off in the middle of a value
        if len(val) < length:
            break
        # option 12 = the device's name
        if code == 12 and val:
            name = clean_text(val)
            if name:
                info["hostname"] = name
        # option 50 = the IP it's asking for
        elif code == 50 and length == 4:
            info["ip"] = socket.inet_ntoa(val)
        # option 60 = "vendor class"
        elif code == 60 and val:
            # this says what software asked, like "android-dhcp-14" or "MSFT 5.0" (Windows).
            # it's NOT who made the device, so we save it as dhcp_class, not vendor
            info["dhcp_class"] = clean_text(val)
        # skip to the next option (code + length + value)
        i += 2 + length
    return mac, info


#
# Class: ListenerError - the error we raise when we can't start listening.
# The message says why in normal words.
#
class ListenerError(Exception):
    pass


#
# Function: open_socket - Open the socket that listens on port 67 for DHCP requests.
# Input argument: none
# Output argument: none
# Return: the socket, ready to listen (raises ListenerError if it can't)
# Dependencies: socket - AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, SO_REUSEADDR, SO_REUSEPORT, socket; ListenerError
#
def open_socket():
    # UDP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # lets us listen even if something else used the port recently
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Mac and Linux have this, Windows doesn't
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    # DHCP requests are broadcasts, so we need this to hear them
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        # 0.0.0.0 = listen on every network connection, 67 = the DHCP server port
        s.bind(("0.0.0.0", 67))
    # not running with sudo
    except PermissionError:
        s.close()
        raise ListenerError("permission denied for port 67 (needs sudo/admin)")
    # something else is already using it
    except OSError as e:
        s.close()
        raise ListenerError(f"port 67 is in use ({e}). On a Mac, turn off Internet Sharing "
                            "in System Settings > General > Sharing")
    return s


#
# Function: listen - Keep collecting names forever. A bad packet never stops it.
# Input argument: sock - the open socket listening on port 67
#                 log - the function used to print messages (print by default)
# Output argument: none (but it saves every name it hears to dhcp_names.json)
# Return: none
# Dependencies: load_existing, parse_packet, save
#
def listen(sock, log=print):
    # start with what we already know
    devices = load_existing()
    while True:
        try:
            # wait for the next packet (2048 bytes is more than enough)
            data, _ = sock.recvfrom(2048)
        except OSError as e:
            log(f"DHCP: receive failed ({e}), still listening")
            continue
        try:
            parsed = parse_packet(data)
        # one weird packet shouldn't stop everything
        except Exception as e:
            log(f"DHCP: skipped an unreadable packet ({e})")
            continue
        # not a DHCP request we care about
        if not parsed:
            continue
        mac, new_info = parsed
        # get this device's entry, or make a new empty one
        info = devices.setdefault(mac, {})
        # add the new info but keep anything this packet didn't have
        info.update(new_info)
        log(f"DHCP: {mac}  ip={info.get('ip', '?'):<15} hostname={info.get('hostname', '?'):<25} "
            # :<15 pads it so the columns line up
            f"class={info.get('dhcp_class', '?')}")
        save(devices)


#
# Function: start_background - server.py uses this: listen in a background thread. Returns True if it started.
# Input argument: log - the function used to print messages (print by default)
# Output argument: none
# Return: True if the listener started, False if it couldn't
# Dependencies: threading; ListenerError, listen, open_socket
#
def start_background(log=print):
    import threading
    try:
        sock = open_socket()
    # the dashboard still works without names
    except ListenerError as e:
        log(f"Device names (DHCP) are off: {e}")
        return False

    #
    # Function: run
    # Input argument: none
    # Output argument: none
    # Return: none
    # Dependencies: listen
    #
    def run():
        try:
            listen(sock, log)
        except Exception as e:
            log(f"Device names (DHCP) stopped: {e}")

    # daemon = stops when server.py stops
    threading.Thread(target=run, name="dhcp-listener", daemon=True).start()
    log("Listening for device names (DHCP). Reconnect a device to Wi-Fi to pick up its name.")
    return True


#
# Function: main - Running this file on its own.
# Input argument: none
# Output argument: none
# Return: none
# Dependencies: pathlib - Path; sys - executable, exit; ListenerError, listen, open_socket
#
def main():
    try:
        sock = open_socket()
    except ListenerError as e:
        sys.exit(f"Couldn't start: {e}.\nRun it as admin: sudo {sys.executable} {Path(__file__).name}")
    print("Listening for DHCP... reconnect devices now (Ctrl+C to stop)")
    print(f"Saving to {OUT_FILE}")
    listen(sock)


if __name__ == "__main__":
    try:
        main()
    # Ctrl+C
    except KeyboardInterrupt:
        print(f"\nStopped. Names are saved in {OUT_FILE.name}")
