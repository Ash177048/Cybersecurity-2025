import scapy.all as scapy
import argparse
import re

# Get arguments from the command line
def get_arguments():
    """
    Parses command-line arguments for the network scanner.
    """
    parser = argparse.ArgumentParser(description="A Python-based Network Scanner utility.")
    parser.add_argument("-t", "--target", dest="ip", help="Specify IP address or range (e.g., 192.168.1.1/24)", required=True)
    parser.add_argument("-o", "--output", dest="output_file", help="Save results to a file (e.g., results.txt)")
    parser.add_argument("--timeout", dest="timeout", type=int, default=1, help="Set timeout for responses (default: 1 second)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    options = parser.parse_args()
    return options

# Validate IP address or range
def validate_ip(ip):
    """
    Validates the format of the IP address or range.
    """
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/(1[0-9]|[1-9]|2[0-4])|/3[0-2])?$")
    if not ip_pattern.match(ip):
        raise ValueError("[-] Invalid IP address or range. Use format: 192.168.1.1 or 192.168.1.1/24")
    return True

# Scan the network for clients
def scan(ip, timeout, verbose):
    """
    Sends ARP requests to the target IP range and collects responses.
    
    Args:
        ip (str): IP address or range to scan.
        timeout (int): Timeout for ARP requests.
        verbose (bool): Whether to enable verbose output.
    
    Returns:
        list: A list of dictionaries containing IP and MAC addresses.
    """
    try:
        # Create ARP request and broadcast frame
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Send the packet and get the response
        answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=verbose)[0]
        
        # Extract client IP and MAC addresses
        client_list = [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]
        return client_list
    except Exception as e:
        print(f"[-] Error scanning the network: {e}")
        return []

# Print the results
def print_result(result_list):
    """
    Displays the scan results in a formatted table.
    """
    print("\nScan Results:")
    print("IP Address\t\tMAC Address")
    print("------------------------------------------")
    for client in result_list:
        print(f"{client['ip']}\t\t{client['mac']}")

# Save results to a file
def save_results(result_list, filename):
    """
    Saves the scan results to a file.
    
    Args:
        result_list (list): List of dictionaries containing IP and MAC addresses.
        filename (str): Name of the output file.
    """
    try:
        with open(filename, "w") as file:
            file.write("IP Address\tMAC Address\n")
            file.write("------------------------------------------\n")
            for client in result_list:
                file.write(f"{client['ip']}\t{client['mac']}\n")
        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Error saving results: {e}")

# Main function
def main():
    """
    Main function to execute the Network Scanner.
    """
    # Parse arguments
    options = get_arguments()

    # Validate IP range
    try:
        validate_ip(options.ip)
    except ValueError as ve:
        print(ve)
        return

    # Scan the network
    print(f"[*] Scanning the network for range: {options.ip}")
    scan_result = scan(options.ip, options.timeout, options.verbose)

    # Display results
    if scan_result:
        print_result(scan_result)

        # Save results to a file if specified
        if options.output_file:
            save_results(scan_result, options.output_file)
    else:
        print("[-] No devices found. Ensure the IP range is correct and retry.")

if __name__ == "__main__":
    main()
