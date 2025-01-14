import subprocess
import logging
import time
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

# Ports and services to protect
PROTECTED_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 3306: "MySQL",
    1433: "MSSQL", 3389: "RDP", 27017: "MongoDB", 6379: "Redis",
    53: "DNS", 69: "TFTP", 110: "POP3", 111: "RPC", 135: "MS RPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 445: "SMB",
    512: "exec", 513: "login", 514: "shell", 873: "rsync", 1080: "SOCKS",
    1521: "Oracle DB", 2049: "NFS", 2121: "FTP", 3306: "MySQL", 5432: "PostgreSQL",
    5900: "VNC", 6000: "X11", 8080: "HTTP Proxy", 8443: "HTTPS Alt", 8888: "HTTP Alt"
}

# Limits for brute force protection
ATTEMPT_LIMIT = 5
BLOCK_DURATION = 600  # In seconds

# Track connection attempts
attempt_tracker = defaultdict(list)

# Function to add a block rule
def block_ip(ip):
    logger.info(f"Blocking IP: {ip}")
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error adding block rule: {e}")

# Function to remove a block rule
def unblock_ip(ip):
    logger.info(f"Unblocking IP: {ip}")
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error removing block rule: {e}")

# Main function to monitor connection attempts
def monitor_connections():
    while True:
        # Simulate getting connection logs (replace with actual source, e.g., fail2ban or syslog)
        logs = get_mock_logs()
        for log in logs:
            ip, port = log["ip"], log["port"]
            if port in PROTECTED_PORTS:
                attempt_tracker[ip].append(time.time())
                # Filter attempts by time
                attempt_tracker[ip] = [t for t in attempt_tracker[ip] if time.time() - t < BLOCK_DURATION]
                if len(attempt_tracker[ip]) > ATTEMPT_LIMIT:
                    block_ip(ip)
                    # Clear tracking for blocked IP
                    attempt_tracker[ip] = []
        time.sleep(5)

# Function to simulate getting logs (replace with actual)
def get_mock_logs():
    return [
        {"ip": "192.168.1.100", "port": 22},
        {"ip": "192.168.1.101", "port": 3389},
        {"ip": "192.168.1.102", "port": 3306},
    ]

if __name__ == "__main__":
    try:
        logger.info("Starting connection monitoring")
        monitor_connections()
    except KeyboardInterrupt:
        logger.info("Stopping script")
