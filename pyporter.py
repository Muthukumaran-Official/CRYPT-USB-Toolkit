import socket
import re
import os
import time
import signal
import threading
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Handle Ctrl+C for a clean exit
def signal_handler(sig, frame):
    print(Fore.RED + "\n[!] Scan interrupted by user. Stopping scan..." + Style.RESET_ALL)
    global scanning
    scanning = False
    input("\n[!] Scan interrupted. Press Enter to exit...")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Regex patterns for validation
ip_add_pattern_v4 = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
ip_add_pattern_v6 = re.compile("^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$")
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

# Common ports professionals check first
common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 3306, 8080, 5900, 1723, 636, 993, 995, 500, 4500, 5357, 2049, 1080]
open_ports = set()

# Load banner
script_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(script_dir, "banner.txt")
try:
    with open(file_path, "r") as file:
        banner = file.read()
    print(Fore.GREEN + banner + Style.RESET_ALL)
except FileNotFoundError:
    print(Fore.RED + "[!] Banner file not found. Proceeding without banner." + Style.RESET_ALL)

# Get and validate the IP address
while True:
    ip_add_entered = input("\nEnter the IP address: ")
    if ip_add_pattern_v4.search(ip_add_entered):
        ip_version = 4
        print(f"{Fore.CYAN}IPv4 detected: {ip_add_entered}{Style.RESET_ALL}")
        break
    elif ip_add_pattern_v6.search(ip_add_entered):
        ip_version = 6
        print(f"{Fore.CYAN}IPv6 detected: {ip_add_entered}{Style.RESET_ALL}")
        break
    else:
        print(Fore.RED + "Invalid IP address. Please enter a valid IPv4 or IPv6 address." + Style.RESET_ALL)

# Function to scan a port
def scan_port(port):
    global scanning
    if not scanning:
        return
    try:
        family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((ip_add_entered, port))
            if port not in open_ports:
                open_ports.add(port)
                print(f"{Fore.GREEN}[OPEN] Port {port} is open{Style.RESET_ALL}")
    except:
        print(f"{Fore.RED}[CLOSED] Port {port} is closed{Style.RESET_ALL}")

# Scan common ports first
scanning = True
print("\n[+] Scanning common ports...\n")
threads = []
for port in common_ports:
    thread = threading.Thread(target=scan_port, args=(port,))
    threads.append(thread)
    thread.start()
    time.sleep(0.05)  # Slight delay to control output pacing
for thread in threads:
    thread.join()

# Function to get service details
def get_port_details(port):
    try:
        return socket.getservbyport(port)
    except (socket.error, OSError):
        return 'Unknown Service'

# Ask for custom range even if open ports are found in common ports
print(Fore.YELLOW + "\n[!] Common port scan complete. Do you want to scan a custom range? (yes/no)" + Style.RESET_ALL)
choice = input().strip().lower()
if choice == 'yes':
    while True:
        port_range = input("Enter port range (e.g., 1-65535): ")
        port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
        if port_range_valid:
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            break
    print("\n[+] Starting full port scan...\n")
    threads = []
    for port in range(port_min, port_max + 1):
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
        time.sleep(0.02)  # Slight delay to prevent flooding output
    for thread in threads:
        thread.join()

# Display open ports and services
print("\n[+] Open ports and services:")
if open_ports:
    for port in sorted(open_ports):
        print(f"{Fore.GREEN}[OPEN] Port {port}: {Fore.CYAN}{get_port_details(port)}{Style.RESET_ALL}")
else:
    print(Fore.RED + "No open ports found." + Style.RESET_ALL)

input("\n[!] Scan complete. Press Enter to exit...")
