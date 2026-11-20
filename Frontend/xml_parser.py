# xml_parser.py - reads the XML files nmap saves and turns them into a normal Python list
#
# main.py saves nmap's raw results as discovery_results.xml and scan_results.xml.
# This reads one of those files and gives back a list of hosts like:
#
#     [{"ip": "192.168.1.1", "hostname": "Router", "mac": "...", "vendor": "Netgear",
#       "status": "up", "os": "Linux 3.x", "accuracy": 95,
#       "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http", ...}]}]
#
# That's the format vulnerability_identifier.determine_vulnerability() expects,
# so you can do: determine_vulnerability(parse_results("scan_results.xml"))

# to check the IP when guessing a name
import ipaddress
# Python's built-in XML reader
import xml.etree.ElementTree as ET


#
# Function: _to_int - Turn text like "95" into the number 95. Gives `default` if it isn't a number (or is missing).
# Input argument: value - the text to turn into a number
#                 default - what to give back if it isn't a number
# Output argument: none
# Return: the number, or `default`
# Dependencies: none
#
def _to_int(value, default=None):
    try:
        return int(value)
    # None or something like "abc"
    except (TypeError, ValueError):
        return default


#
# Function: _fallback_name - If nmap found no name: "Router" for x.x.x.1 (usually the router), otherwise "IoT Device".
# Input argument: ip_address - the device's IP address
# Output argument: none
# Return: "Router", "IoT Device" or "Unknown device"
# Dependencies: ipaddress - ip_address
#
def _fallback_name(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
    # no IP or not a real IP
    except (TypeError, ValueError):
        return "Unknown device"
    if ip.version == 4 and str(ip).endswith(".1"):
        return "Router"
    return "IoT Device"


#
# Function: parse_results - Read an nmap XML file and give back a list of hosts.
# Input argument: filename - the file to read or write
# Output argument: none
# Return: a list of hosts, or [] if the file can't be read
# Dependencies: xml.etree.ElementTree - ParseError, parse; _fallback_name, _to_int
#
def parse_results(filename):
    # If the file is missing, empty or not nmap XML, it prints why and gives back []
    # so whatever called it doesn't crash.
    try:
        # read and parse the whole file
        tree = ET.parse(filename)
    except FileNotFoundError:
        print(f"{filename} doesn't exist yet. Run a scan first.")
        return []
    # broken XML, usually because the scan was stopped halfway
    except ET.ParseError as e:
        print(f"{filename} isn't valid nmap XML ({e}). The scan may have been stopped early.")
        return []

    # the <nmaprun> tag at the top
    root = tree.getroot()
    hosts = []
    # every <host> tag is one device
    for host in root.findall('host'):
        # get the IP address (IPv4 first, then IPv6 if there's no IPv4)
        # <address addr="..." addrtype="ipv4"/>
        find_ip = host.find('address[@addrtype="ipv4"]')
        if find_ip is None:
            find_ip = host.find('address[@addrtype="ipv6"]')
        ip_address = find_ip.get('addr') if find_ip is not None else None

        # get the name (or make one up if nmap didn't find one)
        # <hostnames><hostname name="..."/></hostnames>
        find_hostname = host.find('hostnames/hostname')
        if find_hostname is not None and find_hostname.get('name'):
            hostname = find_hostname.get('name')
        else:
            hostname = _fallback_name(ip_address)

        # get the MAC address and maker (nmap only has these with sudo)
        find_mac = host.find('address[@addrtype="mac"]')
        if find_mac is not None:
            mac_address = find_mac.get('addr')
            # nmap looks up the maker for us
            vendor = find_mac.get('vendor')
        else:
            mac_address = None
            vendor = None

        # is it up or down
        find_status = host.find('status')
        status = find_status.get('state') if find_status is not None else None

        # operating system guess (the first <osmatch> is nmap's best guess)
        find_os = host.find('os/osmatch')
        if find_os is not None:
            os = find_os.get('name')
            # how sure nmap is, out of 100
            accuracy = _to_int(find_os.get('accuracy'))
        else:
            os = None
            accuracy = None

        # all the ports for this host go in here
        ports = []

        # every <port> tag
        for port in host.findall('ports/port'):
            # the port number
            port_id = _to_int(port.get('portid'))
            # skip any without a number
            if port_id is None:
                continue

            # open, closed or filtered
            find_state = port.find('state')
            state = find_state.get('state') if find_state is not None else None

            # what's running on it (only there if nmap was run with -sV)
            find_service = port.find('service')
            if find_service is not None:
                # e.g. "http"
                service = find_service.get('name')
                # e.g. "nginx"
                product = find_service.get('product')
                # e.g. "1.18"
                version = find_service.get('version')
            else:
                service = None
                product = None
                version = None

            # save this port
            ports.append({
                'port': port_id,
                # "tcp" or "udp"
                'protocol': port.get('protocol'),
                'state': state,
                'service': service,
                'product': product,
                'version': version
            })

        # save this host
        hosts.append({
            'ip': ip_address,
            'hostname': hostname,
            'mac': mac_address,
            'vendor': vendor,
            'status': status,
            'os': os,
            'accuracy': accuracy,
            'ports': ports
        })
    return hosts
