#!/usr/bin/env python3
import socket
import sys
from datetime import datetime

def get_service_name(port):
    """Returns the standard service name for a port (e.g., 80 -> HTTP)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"

def clean_target(user_input):
    """Strip the protocol and path if the user pastes a full URL."""
    target = user_input.strip()
    if "://" in target:
        target = target.split("://")[1]
    return target.split("/")[0]

def scan_port(target_ip, port):

    """Attempt to connect to a specific port on the target IP.
    Returns True if the port is open, False otherwise."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(0.2)
            code = client.connect_ex((target_ip, port))
            return code == 0  
    except socket.error:
        return False

def main():
    print("="*45)
    print("           NETWORK PORT SCANNER v1.0         ")
    print("="*45)
    
    # Dynamic Target: User inputs the address instead of hardcoding
    raw_target = input("[?] Enter the target IP or domain: ")
    target = clean_target(raw_target)

    if not target:
        print("\n[-] Error: No target provided.")
        sys.exit(1)
    
    # List of main ports to check
    ports = [21, 22, 25, 80, 443, 445, 3306]
    
    try:
        # Ensures that if the user types a domain, it gets converted to an IP
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("\n[-] Error: Invalid hostname or DNS resolution failure.")
        sys.exit(1)

    print(f"\n[*] Starting scan on target: {target} ({target_ip})")
    print("-" * 45)
    
    open_ports = 0
    start_time = datetime.now()

    for port in ports:
        if scan_port(target_ip, port):
            service_name = get_service_name(port)
            print(f"[+] Port {port:<5}/TCP : OPEN ({service_name})")
            open_ports += 1

    duration = (datetime.now() - start_time).total_seconds()
    print("-" * 45)
    print(f"[*] Scan completed in {duration:.2f}s! {open_ports} open port(s) found.")

if __name__ == "__main__":
    # Allows interrupting the script with Ctrl+C without showing ugly traceback errors
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user.")
        sys.exit(0)