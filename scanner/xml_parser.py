import xml.etree.ElementTree as ET

def parse_results(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    hosts = []
    for host in root.findall('host'):
        # get ip address 
        find_ip = host.find('address[@addrtype="ipv4"]')

        if find_ip is not None:
            ip_address = find_ip.get('addr')
        else:
            ip_address = None

        # find hostname
        find_hostname = host.find('hostnames/hostname')

        if find_hostname is not None:
            hostname = find_hostname.get('name')
        else:
            address = ip_address.split(".")

            if address[3] == "1":
                hostname = "Router"
            else:
                hostname = "IoT Device"

        # get mac address
        find_mac = host.find('address[@addrtype="mac"]')

        if find_mac is not None:
            mac_address = find_mac.get('addr')
            vendor = find_mac.get('vendor')
        else:
            mac_address = None
            vendor = None

        # get device status
        find_status = host.find('status')

        if find_status is not None:
            status = find_status.get('state')
        else:
            status = None

        # get operating system
        find_os = host.find('os/osmatch')

        if find_os is not None:
            os = find_os.get('name')
            accuracy = int(find_os.get('accuracy'))
        else:
            os = None
            accuracy = None

        # store ports
        ports = []

        # get all port information
        for port in host.findall('ports/port'):

            # find port state
            find_state = host.find('state')

            if find_state is not None:
                state = find_state.get('state')
            else:
                state = None

            # find port service
            find_service = host.find('service')

            if find_service is not None:
                service = find_service.get('name')
                product = find_service.get('product')
                version = find_service.get('version')
            else:
                service = None
                product = None
                version = None

            # find port
            port = int(port.get('portid'))

            # find protocol
            protocol = port.get('protocol')

            port_info = {
                'port': port,
                'protocol': protocol,
                'state': state,
                'service': service,
                'product': product,
                'version': version
            }

            # add port information to array
            ports.append(port_info)

        # add host information to array
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