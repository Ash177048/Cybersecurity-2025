# Port Network Scanner 
A Python-based tool for scanning networks and discovering connected devices. This simple yet powerful script identifies devices on a local network by sending ARP requests and capturing responses.

## Features
- 🔍 **Quick Network Scanning**: Discover all devices connected to your network.
- 🖥️ **IP and MAC Address Detection**: Lists the IP and MAC addresses of devices.
- 💾 **Save Scan Results**: Option to export the scan results to a file (e.g., `scan_results.txt`).
- 🛠️ **Customizable**: Easy to extend with additional features like port scanning or advanced analysis.

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
- `sudo python3 network_scanner.py -t 192.168.129.2`
- `sudo python3 network_scanner.py --target 192.168.129.1/24`
