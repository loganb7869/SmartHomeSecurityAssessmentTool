import json

def manufacturer(mac_address, hostname):
    current = mac_address.split(":")
    result = []
    for i in range(len(current)//2):
        result.append(current[i])
    result = ":".join(result)
    
    with open('mac-vendors-export.json', 'r', encoding='utf-8') as file:
        data = json.load(file)
    
    manufacturer_name = "unkown manufacturer"
    
    for j in data:
        if result.upper() == j['macPrefix'].upper(): 
            manufacturer_name = j['vendorName']
            break
    
    return {
        "manufacturer": manufacturer_name,
        "model": hostname
    }

