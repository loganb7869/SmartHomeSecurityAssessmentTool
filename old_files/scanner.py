'''
DISCLAIMER: This script is developed using the nmap-python library which is a wrapper for the NMAP network scanner program published by the nmap.org website at: https://nmap.org/download.html

The code below performs identification of hosts, scanning of TCP ports using SYN packets, operating system detection, and detection of service detection.

Commands used:
    - "-sn": Disable port scan and discover devices
    - "-sS": TCP SYN scan
    - "-sV": Probe open ports to determine service/version info
    - "-O": Operating system detection
    - "-p 1-1000": Port range from 1 to 1000
    - "-oX": Saves the results of the scan into a XML format
'''
import nmap

# store the port scanner function
nm = nmap.PortScanner()

# store the item to be scanned | replace with IPv4 address of local network
scanned_item = "scanme.nmap.org"

# discover devices
nm.scan(scanned_item, arguments="-sn -oX discovery_results.xml")

# loop through all returned hosts
for host in nm.all_hosts():
    print("-------------------------")
    print("IP Address: ", host)
    print("State: ", nm[host].state())

    if "mac" in nm[host]["addresses"]:
        print("MAC Address:", nm[host]["addresses"]["mac"])
    
    hostname = nm[host].hostname()
    if hostname:
        print("Hostnames:", hostname)

# scan ports, services, and detect operating system
scan_options = "-sS -sV -O -p 1-1000 -oX scan_results.xml"

# output scan parameters
print(f"Starting scan on {scanned_item} with options: {scan_options}...")

# perform the scan
nm.scan(scanned_item, arguments=scan_options)

# loop through all returned hosts
for host in nm.all_hosts():
    print("-------------------------")
    print("IP Address: ", host)
    print("State: ", nm[host].state())

    # for all protocols
    for proto in nm[host].all_protocols():
        # print the protocol
        print("Protocol: ", proto)

        # store the ports for the host under that protocol
        ports = sorted(nm[host][proto].keys())

        # loop through each port and print information for each
        for port in ports:
            port_state = nm[host][proto][port]['state']
            port_name = nm[host][proto][port]['name']
            print(f"Port: {port:<5} State: {port_state:<8} Service: {port_name}")