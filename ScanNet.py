import socket
import psutil

# Функция для сканирования одного порта
def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Таймаут в 1 секунду
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return True
        return False
    except socket.error:
        return False

# Функция для сканирования диапазона портов
def scan_ports(host, ports):
    open_ports = []
    for port in ports:
        if scan_port(host, port):
            open_ports.append(port)
    return open_ports

# Проверка на уязвимые порты с добавлением новых сервисов
def check_vulnerabilities(host, open_ports):
    known_vulnerable_ports = {
        21: "FTP", 
        22: "SSH", 
        23: "Telnet", 
        25: "SMTP", 
        3306: "MySQL",      # Порт MySQL
        1433: "MSSQL",      # Порт MSSQL
        3389: "RDP",        # Порт RDP
        27017: "MongoDB",   # Порт MongoDB
        6379: "Redis"       # Порт Redis
    }
    vulnerable_ports = []

    for port in open_ports:
        if port in known_vulnerable_ports:
            vulnerable_ports.append((port, known_vulnerable_ports[port]))

    return vulnerable_ports


# Получение списка всех подключенных IP-адресов на ПК
def get_connected_ips():
    connected_ips = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            connected_ips.append(conn.raddr[0])
    return set(connected_ips)

# Функция для отображения краткой информации о процессах
def process_scanning():
    print(f"{'PID':<10}{'Name':<25}{'Status':<15}{'Memory (MB)':<15}")
    print("=" * 65)
    for proc in psutil.process_iter(['pid', 'name', 'status', 'memory_info']):
        try:
            mem = proc.info['memory_info'].rss / (1024 * 1024)  # Конвертация в MB
            print(f"{proc.info['pid']:<10}{proc.info['name']:<25}{proc.info['status']:<15}{mem:<15.2f}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# Функция для отображения полной информации о процессе по его имени
def calculating_information_from_a_process(process_name):
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'status', 'create_time', 'cpu_times', 'memory_info', 'exe', 'cmdline']):
        try:
            if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
                print(f"\nПолная информация о процессе '{proc.info['name']}' (PID: {proc.info['pid']}):")
                print(f"PID: {proc.info['pid']}")
                print(f"Имя: {proc.info['name']}")
                print(f"Пользователь: {proc.info['username']}")
                print(f"Статус: {proc.info['status']}")
                print(f"Время запуска: {psutil.datetime.datetime.fromtimestamp(proc.info['create_time']).strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Время CPU (user/system): {proc.info['cpu_times'].user:.2f}s / {proc.info['cpu_times'].system:.2f}s")
                print(f"Используемая память: {proc.info['memory_info'].rss / (1024 * 1024):.2f} MB")
                print(f"Исполняемый файл: {proc.info['exe']}")
                print(f"Аргументы командной строки: {' '.join(proc.info['cmdline'])}")

                # Добавление информации о подключении
                connections = proc.connections()
                for conn in connections:
                    if conn.raddr:
                        print(f"Подключен к: {conn.raddr.ip}:{conn.raddr.port}")
                    else:
                        print("Подключения отсутствуют или недоступны.")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# Главная программа с меню
def main():
    while True:
        print("\nГлавное меню:")
        print("1. Проверка одного IP адреса вручную")
        print("2. Проверка всех подключенных IP адресов на ПК")
        print("3. Просмотр информации о процессах")
        print("4. Выход")
        
        command = input("Выберите команду (1/2/3/4): ")

        if command == '1':
            target_host = input("Введите IP адрес для проверки (например, 192.168.1.1): ")
            ports_to_scan = [21, 22, 23, 25, 80, 443]
            print(f"Сканирование {target_host}...")
            open_ports = scan_ports(target_host, ports_to_scan)

            if open_ports:
                print(f"Открытые порты на {target_host}: {open_ports}")
                vulnerabilities = check_vulnerabilities(target_host, open_ports)
                if vulnerabilities:
                    print("Обнаружены уязвимые порты:")
                    for port, service in vulnerabilities:
                        print(f"Порт {port} ({service}) может быть уязвим.")
                else:
                    print("Уязвимости не найдены.")
            else:
                print("Открытые порты не найдены.")
        
        elif command == '2':
            print("Проверка всех подключенных IP адресов на ПК...")
            connected_ips = get_connected_ips()

            if connected_ips:
                print("Подключенные IP адреса:")
                for ip in connected_ips:
                    print(ip)
                print("Проверка портов на этих IP адресах...")
                for ip in connected_ips:
                    open_ports = scan_ports(ip, [21, 22, 23, 25, 80, 443])
                    if open_ports:
                        print(f"Открытые порты на {ip}: {open_ports}")
                        vulnerabilities = check_vulnerabilities(ip, open_ports)
                        if vulnerabilities:
                            print("Обнаружены уязвимые порты:")
                            for port, service in vulnerabilities:
                                print(f"Порт {port} ({service}) может быть уязвим.")
                        else:
                            print(f"На {ip} уязвимости не найдены.")
            else:
                print("Нет подключенных IP-адресов.")
        
        elif command == '3':
            print("Просмотр информации о процессах...")
            print("1. Просмотр всех процессов")
            print("2. Получение информации о процессе по имени")
            sub_command = input("Выберите команду (1/2): ")

            if sub_command == '1':
                process_scanning()
            elif sub_command == '2':
                process_name = input("Введите имя процесса: ")
                calculating_information_from_a_process(process_name)
            else:
                print("Некорректная команда. Попробуйте снова.")
        
        elif command == '4':
            print("Выход из программы.")
            break
        
        else:
            print("Некорректная команда. Попробуйте снова.")

# Запуск программы
if __name__ == "__main__":
    main()
