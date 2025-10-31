import re
import sys
import ipaddress
from datetime import datetime
from pathlib import Path

# ============================================================================
# ACCESS CONTROL SECURITY CHECK SYSTEM
# ============================================================================
# This script monitors system logs for unauthorized IP access attempts.
# It compares all IPs found in a log file against an approved whitelist.
# If unauthorized IPs are detected, it reports them with occurrence counts
# to help identify potential security threats.
# ============================================================================

def valid_ip(ip):
    """
    Verify that an IP address is a valid IPv4 format.
    
    This function ensures the IP is within the valid range.
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def load_allowed_ips(allowed_list):
    """
    Read and load the approved IP addresses from a file.
    
    Returns a set of approved IPs, or None if the file cannot be read.
    """
    allowed_list = Path(allowed_list)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"[{timestamp}] Loading allowed IPs from: {allowed_list}")
    
    if not allowed_list.exists():
        print(f"ERROR: Allow list file not found: {allowed_list}")
        return None
    
    allowed_ips = set()
    try:
        with open(allowed_list, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                ip = line.strip()
                
                # Skip empty lines and comments
                if not ip or ip.startswith('#'):
                    continue
                
                # Only add valid IPs to the allowed list
                if valid_ip(ip):
                    allowed_ips.add(ip)
                else:
                    print(f"WARNING: Invalid IP format on line {line_num}: {ip}")
    
    except IOError as e:
        print(f"ERROR: Failed to read allow list: {e}")
        return None
    
    print(f"Successfully loaded {len(allowed_ips)} allowed IP(s)\n")
    return allowed_ips

def extract_ips_from_log(log_path):
    """
    Scan the system log and extract all IP addresses found.
    
    This function searches through the log file for IPv4 addresses
    and counts how many times each one appears. This helps identify
    repeated access attempts from the same source.
    
    Returns each IP with an occurrence count, or None if the file cannot be read.
    """
    log_path = Path(log_path)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"[{timestamp}] Scanning log file: {log_path}")
    
    if not log_path.exists():
        print(f"ERROR: Log file not found: {log_path}")
        return None
    
    ip_counts = {}
    
    # Pattern to find IPv4 addresses in the log
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    try:
        with open(log_path, 'r', encoding='utf-8') as file:
            content = file.read()
            matches = re.findall(ip_pattern, content)
            
            # Count each IP's appearances in the log
            for ip in matches:
                if valid_ip(ip):
                    if ip in ip_counts:
                        ip_counts[ip] += 1
                    else:
                        ip_counts[ip] = 1
    
    except IOError as e:
        print(f"ERROR: Failed to read log file: {e}")
        return None
    
    print(f"Found {len(ip_counts)} unique IP address(es) in log\n")
    return ip_counts

def report_findings(allowed, logged_ips, unauthorized_ips):
    """
    Display a report of the access control check.
    
    This report shows:
    - How many IPs are on the approved list
    - How many unique IPs appeared in the log
    - How many total log entries were processed
    - How many entries came from authorized vs unauthorized sources
    - A list of all unauthorized IPs and how many times they appeared
    
    High occurrence counts for unauthorized IPs may indicate
    malicious scanning activity.
    """
    total_log_entries = sum(logged_ips.values())
    authorized_entries = sum(count for ip, count in logged_ips.items() if ip not in unauthorized_ips)
    
    print("\n--- SECURITY REPORT ---\n")
    print(f"Allowed IPs in system:      {len(allowed)}")
    print(f"Unique IPs found in log:    {len(logged_ips)}")
    print(f"Total log entries:          {total_log_entries}")
    print(f"Authorized log entries:     {authorized_entries}")
    print(f"Unauthorized log entries:   {total_log_entries - authorized_entries}\n")
    
    if not unauthorized_ips:
        print("STATUS: All access is authorized. No action required.\n")
    else:
        print(f"ALERT: Detected {len(unauthorized_ips)} unauthorized IP address(es)!\n")
        print("Unauthorized IPs:")
        for ip in sorted(unauthorized_ips):
            count = logged_ips[ip]
            print(f"  {ip} - Appeared {count} time(s)")
        print()

def run_check(allowed_list, log_path):
    """
    Execute the complete access control security check.
    
    This function orchestrates the entire process:
    1. Load the approved IP whitelist from file
    2. Extract all IPs from the system log
    3. Compare the two lists to find unauthorized access
    4. Generate and display a security report
    
    Returns True if the check completed successfully,
    False if there were errors reading the required files.
    """
    print("=" * 60)
    print("ACCESS CONTROL SYSTEM - AUTOMATED SECURITY CHECK")
    print("=" * 60 + "\n")
    
    # Step 1: Load the approved IPs
    allowed_ips = load_allowed_ips(allowed_list)
    if allowed_ips is None:
        print("FAILED: Cannot proceed without allow list\n")
        return False
    
    # Step 2: Extract IPs from the log
    logged_ips = extract_ips_from_log(log_path)
    if logged_ips is None:
        print("FAILED: Cannot proceed without log file\n")
        return False
    
    # Step 3: Find unauthorized IPs
    print("Analyzing access patterns...")
    unauthorized_ips = {ip for ip in logged_ips if ip not in allowed_ips}
    
    # Step 4: Display the report
    report_findings(allowed_ips, logged_ips, unauthorized_ips)
    
    print("=" * 60)
    print("CHECK COMPLETE")
    print("=" * 60 + "\n")
    
    return True

def main():
    """
    Entry point for the access control system.
    
    This function asks the user for the file paths and runs the security check.
    """
    allowed_list = input("Enter the path to the allowed IP list file: ")
    log_file = input("Enter the path to the log file: ")
    
    success = run_check(allowed_list, log_file)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()