#!/usr/bin/env python3
import socket
import sys

def scan_port(target_ip, port):
    """
    Attempts to connect to a specific port on the target IP.
    Returns True if open, False if closed or filtered.
    """
    try:
        # Creates the socket (IPv4, TCP)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 0.1s timeout for faster scanning
        client.settimeout(0.1)
        
        # connect_ex returns 0 if the connection is successful
        code = client.connect_ex((target_ip, port))
        client.close()
        
        return code == 0
    except Exception:
        return False

def main():
    print("="*45)
    print("           NETWORK PORT SCANNER v1.0         ")
    print("="*45)
    
    # Dynamic Target: User inputs the address instead of hardcoding
    target = input("[?] Enter the target IP or Domain (e.g., google.com): ")
    
    # List of main ports to check
    ports = [21, 22, 25, 80, 443, 445, 3306]
    
    try:
        # Ensures that if the user types a domain, it gets converted to an IP
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("\n[-] Error: Invalid hostname or DNS resolution failure.")
        sys.exit()

    print(f"\n[*] Starting scan on target: {target} ({target_ip})")
    print("-" * 45)
    
    open_ports = 0
    
    for port in ports:
        if scan_port(target_ip, port):
            print(f"[+] Port {port:^4} / TCP : OPEN")
            open_ports += 1
            
    print("-" * 45)
    print(f"[*] Scan complete! {open_ports} open port(s) found.")
    print("="*45)

if __name__ == "__main__":
    # Allows interrupting the script with Ctrl+C without showing ugly traceback errors
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user.")
        sys.exit()