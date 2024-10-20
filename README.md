# PiVPN Nexus

PiVPN Nexus is a robust VPN management system designed to run on a Raspberry Pi. It provides enhanced security features, including multi-hop VPN connections, DNS leak protection, and traffic encryption.

## Features

- Multi-hop VPN connections
- DNS leak detection and prevention
- Perfect Forward Secrecy (PFS)
- Traffic statistics monitoring
- Easy management of VPN providers
- Web-based user interface

## Prerequisites

- Raspberry Pi (3 or newer recommended)
- Raspberry Pi OS (formerly Raspbian)
- Python 3.12
- OpenVPN

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/pivpn-nexus.git
   cd pivpn-nexus
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Set up the configuration file:
   ```
   sudo cp config/vpn_nexus_manager.conf /etc/vpn_nexus_manager.conf
   ```
   Edit the file to add your VPN providers' configurations.

4. Set up the necessary permissions:
   ```
   sudo chmod +x run.py
   ```

## Usage

1. Start the PiVPN Nexus service:
   ```
   sudo -E /home/{user}/{path_to_project}/pivpn-nexus/.venv/bin/python run.py
   ```

2. Access the web interface by navigating to `http://your_raspberry_pi_ip:8000` in your web browser.

3. Use the interface to manage VPN providers, optimize VPN chains, and monitor traffic statistics.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is provided for educational and research purposes only. Ensure you comply with all relevant laws and regulations when using VPN services.
