import os
import socket
import psutil
import subprocess
from art import tprint
from colorama import init, Fore, Back, Style
import tqdm
import pyfiglet
import sys
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama
init()

# Print banner
result = pyfiglet.figlet_format("ScanNet")
print(result)
print(Back.RED + 'Github - https://github.com/Eduard-web-coder/ScanNet')
print(Style.BRIGHT + '' + Style.RESET_ALL)

# Flag for enabling/disabling DDoS protection
anti_ddos_enabled = False  # Protection is disabled by default

# Function to toggle DDoS protection
def toggle_anti_ddos(state):
    global anti_ddos_enabled
    anti_ddos_enabled = state

    if anti_ddos_enabled:
        print("DDoS protection enabled.")
        try:
            if os.path.exists("AntiDDoS.py"):
                subprocess.Popen(['python', 'AntiDDoS.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                print("AntiDDoS.py not found. Ensure it is in the current directory.")
                anti_ddos_enabled = False
        except Exception as e:
            print(f"Error starting protection: {e}")
            anti_ddos_enabled = False
    else:
        print("DDoS protection disabled.")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if 'AntiDDoS.py' in proc.info['name']:
                    proc.terminate()
            except Exception as e:
                print(f"Error stopping protection: {e}")

# Flag for enabling/disabling Port Security
port_security_enabled = False  # Protection is disabled by default

# Function to toggle Port Security
def toggle_port_security(state):
    global port_security_enabled
    port_security_enabled = state

    if port_security_enabled:
        print("Port Security enabled.")
        try:
            if os.path.exists("PortSecurity.py"):
                subprocess.Popen(['python', 'PortSecurity.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                print("PortSecurity.py not found. Ensure it is in the current directory.")
                port_security_enabled = False
        except Exception as e:
            print(f"Error starting Port Security: {e}")
            port_security_enabled = False
    else:
        print("Port Security disabled.")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if 'PortSecurity.py' in proc.info['name']:
                    proc.terminate()
            except Exception as e:
                print(f"Error stopping Port Security: {e}")

# Check if script is run as admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

# Restart script with admin privileges
def restart_with_admin():
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
    except Exception as e:
        print(f"Error restarting with admin privileges: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if not is_admin():
        print("Restarting with admin privileges...")
        restart_with_admin()
        sys.exit(0)

# Scan a single port
def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

# Scan a range of ports with a progress bar
def scan_ports(host, ports):
    open_ports = []
    print(f"Scanning ports on {host}...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in tqdm.tqdm(as_completed(futures), total=len(futures), desc="Scanning"):
            port = futures[future]
            if future.result():
                open_ports.append(port)
    return open_ports

# Check for vulnerable ports
def check_vulnerabilities(host, open_ports):
    known_vulnerable_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 3306: "MySQL",
        1433: "MSSQL", 3389: "RDP", 27017: "MongoDB", 6379: "Redis",
        53: "DNS", 69: "TFTP", 110: "POP3", 111: "RPC", 135: "MS RPC",
        139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 445: "SMB",
        512: "exec", 513: "login", 514: "shell", 873: "rsync", 1080: "SOCKS",
        1521: "Oracle DB", 2049: "NFS", 2121: "FTP", 3306: "MySQL", 5432: "PostgreSQL",
        5900: "VNC", 6000: "X11", 8080: "HTTP Proxy", 8443: "HTTPS Alt", 8888: "HTTP Alt",
        5000: "Flask", 8000: "Django", 27015: "Steam", 25565: "Minecraft"
    }
    vulnerable_ports = [(port, known_vulnerable_ports[port]) for port in open_ports if port in known_vulnerable_ports]
    return vulnerable_ports

# Get local IP addresses
def get_local_ip():
    ip_list = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip_list.append(addr.address)
    return ip_list

# Get all connected IP addresses on the PC
def get_connected_ips():
    return {conn.raddr[0] for conn in psutil.net_connections(kind='inet') if conn.status == 'ESTABLISHED' and conn.raddr}

# Display brief information about processes
def process_scanning():
    print(f"{'PID':<10}{'Name':<25}{'Status':<15}{'Memory (MB)':<15}")
    print("=" * 65)
    for proc in psutil.process_iter(['pid', 'name', 'status', 'memory_info']):
        try:
            mem = proc.info['memory_info'].rss / (1024 * 1024)
            print(f"{proc.info['pid']:<10}{proc.info['name']:<25}{proc.info['status']:<15}{mem:<15.2f}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# Display detailed information about a process by its name
def calculating_information_from_a_process(process_name):
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'status', 'create_time', 'cpu_times', 'memory_info', 'exe', 'cmdline']):
        try:
            if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
                print(f"\nDetailed information about process '{proc.info['name']}' (PID: {proc.info['pid']}):")
                print(f"PID: {proc.info['pid']}")
                print(f"Name: {proc.info['name']}")
                print(f"User: {proc.info['username']}")
                print(f"Status: {proc.info['status']}")
                print(f"Start time: {psutil.datetime.datetime.fromtimestamp(proc.info['create_time']).strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"CPU time (user/system): {proc.info['cpu_times'].user:.2f}s / {proc.info['cpu_times'].system:.2f}s")
                print(f"Memory usage: {proc.info['memory_info'].rss / (1024 * 1024):.2f} MB")
                print(f"Executable: {proc.info['exe']}")
                print(f"Command line arguments: {' '.join(proc.info['cmdline'])}")

                connections = proc.connections()
                for conn in connections:
                    if conn.raddr:
                        print(f"Connected to: {conn.raddr.ip}:{conn.raddr.port}")
                    else:
                        print("No connections or unavailable.")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# Main program with menu
def main():
    while True:
        print("\nMain Menu:")
        print("1. Manually check a single IP address")
        print("2. Check all connected IP addresses on the PC")
        print("3. Check vulnerabilities on the current PC")
        print("4. View process information")
        print("5. Enable/disable DDoS protection")
        print("6. Enable/disable Port Security")
        print("7. Exit")
        
        command = input("Choose a command (1/2/3/4/5/6/7): ")

        if command == '1':
            target_host = input("Enter IP address to check (e.g., 192.168.1.1): ")
            ports_to_scan = [21, 22, 23, 25, 80, 443, 53, 69, 110, 111, 135, 139, 143, 161, 389, 445, 512, 513, 514, 873, 1080, 1521, 2049, 2121, 3306, 5432, 5900, 6000, 8080, 8443, 8888, 5000, 8000, 27015, 25565]
            print(f"Scanning {target_host}...")
            open_ports = scan_ports(target_host, ports_to_scan)

            if open_ports:
                print(f"Open ports on {target_host}: {open_ports}")
                vulnerabilities = check_vulnerabilities(target_host, open_ports)
                if vulnerabilities:
                    print("Vulnerable ports found:")
                    for port, service in vulnerabilities:
                        print(f"Port {port} ({service}) may be vulnerable.")
                else:
                    print("No vulnerabilities found.")
            else:
                print("No open ports found.")
        
        elif command == '2':
            print("Checking all connected IP addresses on the PC...")
            connected_ips = get_connected_ips()

            if connected_ips:
                print("Connected IP addresses:")
                for ip in connected_ips:
                    print(ip)
                print("Checking ports on these IP addresses...")
                with ThreadPoolExecutor(max_workers=1) as executor:
                    futures = {executor.submit(scan_ports, ip, [21, 22, 23, 25, 80, 443, 53, 69, 110, 111, 135, 139, 143, 161, 389, 445, 512, 513, 514, 873, 1080, 1521, 2049, 2121, 3306, 5432, 5900, 6000, 8080, 8443, 8888, 5000, 8000, 27015, 25565]): ip for ip in connected_ips}
                    for future in as_completed(futures):
                        ip = futures[future]
                        try:
                            open_ports = future.result()
                            if open_ports:
                                print(f"Open ports on {ip}: {open_ports}")
                                vulnerabilities = check_vulnerabilities(ip, open_ports)
                                if vulnerabilities:
                                    print("Vulnerable ports found:")
                                    for port, service in vulnerabilities:
                                        print(f"Port {port} ({service}) may be vulnerable.")
                                else:
                                    print(f"No vulnerabilities found on {ip}.")
                        except Exception as e:
                            print(f"Error scanning {ip}: {e}")
            else:
                print("No connected IP addresses.")
        
        elif command == '3':
            print("Checking vulnerabilities on the current PC...")
            local_ips = get_local_ip()
            if not local_ips:
                print("Failed to get IP addresses of your PC.")
                continue

            print("Your local IP addresses:")
            for ip in local_ips:
                print(f"- {ip}")
            
            ports_to_scan = [21, 22, 23, 25, 80, 443, 53, 69, 110, 111, 135, 139, 143, 161, 389, 445, 512, 513, 514, 873, 1080, 1521, 2049, 2121, 3306, 5432, 5900, 6000, 8080, 8443, 8888, 5000, 8000, 27015, 25565]
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {executor.submit(scan_ports, ip, ports_to_scan): ip for ip in local_ips}
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        open_ports = future.result()
                        if open_ports:
                            print(f"Open ports on {ip}: {open_ports}")
                            vulnerabilities = check_vulnerabilities(ip, open_ports)
                            if vulnerabilities:
                                print("Vulnerable ports found:")
                                for port, service in vulnerabilities:
                                    print(f" - Port {port} ({service}) may be vulnerable.")
                            else:
                                print("No vulnerabilities found.")
                        else:
                            print("No open ports found.")
                    except Exception as e:
                        print(f"Error scanning {ip}: {e}")

        elif command == '4':
            print("Viewing process information...")
            print("1. View all processes")
            print("2. Get information about a process by name")
            sub_command = input("Choose a command (1/2): ")

            if sub_command == '1':
                process_scanning()
            elif sub_command == '2':
                process_name = input("Enter process name: ")
                calculating_information_from_a_process(process_name)
            else:
                print("Invalid command. Try again.")
        
        elif command == '5':
            print("1. Enable DDoS protection")
            print("2. Disable DDoS protection")
            sub_command = input("Choose a command (1/2): ")
            if sub_command == '1':
                toggle_anti_ddos(True)
            elif sub_command == '2':
                toggle_anti_ddos(False)
            else:
                print("Invalid command. Try again.")
        
        elif command == '6':
            print("1. Enable Port Security")
            print("2. Disable Port Security")
            sub_command = input("Choose a command (1/2): ")
            if sub_command == '1':
                toggle_port_security(True)
            elif sub_command == '2':
                toggle_port_security(False)
            else:
                print("Invalid command. Try again.")
        
        elif command == '7':
            print("Exiting the program.")
            break
        
        else:
            print("Invalid command. Try again.")

# Run the program
if __name__ == "__main__":
    main()
