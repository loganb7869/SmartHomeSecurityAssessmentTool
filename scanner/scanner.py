'''
DISCLAIMER: This script is developed using the python-nmap library which is a wrapper for the NMAP network scanner program published by the nmap.org website at: https://nmap.org/download.html

The code below performs identification of hosts, scanning of TCP ports using SYN packets, operating system detection, service detection, and filtering results by device type.

Commands used:
    - "-sn": Disable port scan and discover devices
    - "-sS": TCP SYN scan
    - "-sV --version-light": Quick probe of open ports for service/version info
    - "-O --osscan-limit": Operating system detection on promising hosts only
    - "--top-ports 100": Scan the 100 most common ports
    - "-T4": Faster timing
'''
import nmap
from device_type_guesser import guess_type, TYPES

def discover_hosts(address):
    choice = ""
    while choice not in TYPES:
        choice = input("Scan for (computer, mobile, console, all): ").strip().lower()
    nm = nmap.PortScanner()

    # your local network
    target = address  

    # performs the scan
    nm.scan(hosts=target, arguments="-sn -T4 -R")
    live = [h for h in nm.all_hosts() if nm[h].state() == "up"]
    with open("discovery_results.xml", "wb") as f:
        f.write(nm.get_nmap_last_output())

    # loop through all returned hosts
    for host in live:
        print("-------------------------")
        print("IP Address:", host)
        address = host.split(".")
        if address[3] == "1":
            print("Hostname: Router")
        else:
            print("Hostname: IoT Device")
        print("MAC Address:", nm[host]["addresses"].get("mac", "n/a"))

    if not live:
        print("No live hosts found.")
        raise SystemExit

    print("-------------------------")
    scan_hosts(live, choice)

def scan_hosts(live, choice):
    nm = nmap.PortScanner()
    # detailed scan, only on live/active hosts
    scan_options = "-sS -sV --version-light -O --osscan-limit --top-ports 100 -T4"
    print(f"Scanning {len(live)} hosts with: {scan_options}")
    nm.scan(hosts=" ".join(live), arguments=scan_options)
    with open("scan_results.xml", "wb") as f:
        f.write(nm.get_nmap_last_output())

    shown = 0
    for host in nm.all_hosts():
        dtype = guess_type(nm, host)
        if choice != "all" and dtype != choice:
            continue
        shown += 1
        print("-------------------------")
        print("IP Address:", host)
        address = host.split(".")
        if address[3] == "1":
            print("Hostname: Router")
        else:
            print("Hostname: IoT Device")
        print("Device type:", dtype)
        print("State:", nm[host].state())
        if nm[host].get("osmatch"):
            print("OS guess:", nm[host]["osmatch"][0]["name"])
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto]):
                p = nm[host][proto][port]
                print(f"Port: {port:<5} State: {p['state']:<8} Service: {p['name']} {p.get('product','')} {p.get('version','')}")

    print(f"\n{shown} device(s) matched '{choice}'.")
