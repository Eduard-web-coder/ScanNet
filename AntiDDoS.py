import time
import psutil
from collections import Counter
from datetime import datetime
from threading import Thread

# Monitoring parameters
MONITOR_INTERVAL = 10  # Interval in seconds for monitoring
THRESHOLD = 100        # Threshold for anomalous activity (e.g., more than 100 requests in MONITOR_INTERVAL seconds)

# Counter for tracking connections by IP
ip_counter = Counter()

# Function to monitor network connections
def monitor_connections():
    while True:
        # Get current network connections
        connections = psutil.net_connections(kind='inet')
        current_ips = [conn.raddr.ip for conn in connections if conn.status == 'ESTABLISHED' and conn.raddr]

        # Update counter for each IP address
        ip_counter.clear()
        ip_counter.update(current_ips)

        # Check for anomalous activity
        print(f"[{datetime.now()}] Checking connections...")
        for ip, count in ip_counter.items():
            if count > THRESHOLD:
                print(f"🚨 Anomalous activity from IP {ip}: {count} connections!")
        
        # Wait before the next check cycle
        time.sleep(MONITOR_INTERVAL)

# Function to start monitoring in a separate thread
def start_monitoring():
    monitor_thread = Thread(target=monitor_connections, daemon=True)
    monitor_thread.start()
    print("Starting DDoS/DoS attack monitoring...")
    while True:
        time.sleep(1)  # Main thread should not terminate, otherwise the program will stop

# Run the program
if __name__ == "__main__":
    start_monitoring()
