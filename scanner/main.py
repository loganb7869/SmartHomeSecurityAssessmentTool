from scanner import discover_hosts

def main():
    address = "192.168.1.0/24"
    discover_hosts(address)

if __name__ == "__main__":
    main()