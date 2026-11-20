# main.py - the terminal version of the scanner (no web page)
#
# How to use it:
#     sudo python3 main.py                        scans 192.168.1.0/24 and asks which devices to show
#     sudo python3 main.py 192.168.0.1            give it ANY IP on your network and it scans the whole network
#     sudo python3 main.py 10.0.0.0/24            or give it the whole network
#     sudo python3 main.py 10.0.0.0/24 tv         and add a type to skip the question
#
# It prints every device, marks risky ports (like [Risk: Critical]), and ends
# with the network safety score. For the web page and saved reports, use server.py instead.

# to read what was typed after "main.py"
import sys

# all the real work is in scanner.py
from scanner import discover_hosts, DEFAULT_NETWORK


#
# Function: main
# Input argument: none
# Output argument: none
# Return: none
# Dependencies: scanner.py - DEFAULT_NETWORK, discover_hosts; sys - argv
#
def main():
    # 1st thing typed: the network or IP (or the default)
    address = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_NETWORK
    # 2nd thing typed: the device type (or ask later)
    choice = sys.argv[2].lower() if len(sys.argv) > 2 else None
    try:
        # find devices, then look closer at them
        discover_hosts(address, choice)
    # Ctrl+C
    except KeyboardInterrupt:
        print("\nScan stopped.")


# only run when started directly, not when imported
if __name__ == "__main__":
    main()
