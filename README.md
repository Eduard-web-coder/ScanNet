# ScanNet

ScanNet is a network security tool designed to scan for open ports, check for vulnerabilities, and provide protection against DDoS attacks and brute force attempts.

## Features

- Scan a single IP address for open ports
- Scan all connected IP addresses on the PC
- Check for vulnerabilities on the current PC
- View detailed information about running processes
- Enable/disable DDoS protection
- Enable/disable Port Security

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Eduard-web-coder/ScanNet.git
    cd ScanNet
    ```

2. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

Run the main script with administrator privileges:
```sh
python ScanNet.py
```

### Command Line Arguments

- `ip`: Target IP address
- `port`: Target port
- `size`: Packet size in bytes
- `count`: Number of packets

Example:
```sh
python UPD.py 192.168.1.1 80 1024 100
```

## Files

- `ScanNet.py`: Main script with menu options
- `AntiDDoS.py`: Script for monitoring and protecting against DDoS attacks
- `PortSecurity.py`: Script for monitoring and protecting against brute force attempts
- `UPD.py`: Script for sending UDP packets

## License

This project is licensed under the MIT License.