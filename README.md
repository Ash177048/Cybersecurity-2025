# Port Network Scanner 
A Python-based tool for scanning networks and discovering connected devices. This simple yet powerful script identifies devices on a local network by sending ARP requests and capturing responses.

## Features
- 🔍 **Quick Network Scanning**: Discover all devices connected to your network.
- 🖥️ **IP and MAC Address Detection**: Lists the IP and MAC addresses of devices.
- 💾 **Save Scan Results**: Option to export the scan results to a file (e.g., `scan_results.txt`).
- 🛠️ **Customizable**: Easy to extend with additional features like port scanning or advanced analysis.
- Custom Timeout: Allows setting ARP request timeout via the --timeout flag.
- Verbose Option: Displays detailed Scapy output using the --verbose flag.
- IP Validation: Ensures the user inputs a valid IP address or range.

## 📋 Requirements
- Python 3.8 or higher
- `scapy` library (Install it via pip: `pip install scapy` or `pip3 install scapy-python3`)

## ⚙️ Installation
1. **Clone the Repository**  
   Clone this project to your local machine:
   ```bash
   git clone https://github.com/username/port-network-scanner.git
   cd port-network-scanner

## Example 
Basic Scan :
- `sudo python3 network_scanner.py -t 192.168.129.2`
- `sudo python3 network_scanner.py --target 192.168.129.1/24`

Save Results to File :
- `sudo python3 network_scanner.py -t 192.168.1.1/24 -o results.txt`

Set Timeout and Enable Verbose Output :
- `sudo python3 network_scanner.py -t 192.168.1.1/24 --timeout 2 --verbose`
