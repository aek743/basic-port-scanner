import socket
import subprocess
import ipaddress
import threading

def is_alive(ip):
    try:
        # Windows için '-n' kullanılır
        subprocess.check_output(['ping', '-n', '1', str(ip)])
        return True
    except subprocess.CalledProcessError:
        return False

def scan_ports(ip, ports):
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                print(f"[+] {ip}:{port} açık")
            sock.close()
        except:
            pass

def scan_ip(ip, ports):
    if is_alive(ip):
        print(f"[✓] {ip} aktif")
        scan_ports(ip, ports)

def main():
    network = input("Ağ aralığını gir (örnek: 192.168.1.0/24): ")
    ports_to_scan = [22, 80, 443, 445, 3389]

    try:
        net = ipaddress.IPv4Network(network, strict=False)
    except:
        print("[!] Geçersiz ağ aralığı!")
        return

    print(f"[*] {network} aralığı taranıyor...\n")
    threads = []
    for ip in net:
        t = threading.Thread(target=scan_ip, args=(ip, ports_to_scan))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n[*] Tarama tamamlandı.")

if __name__ == "__main__":
    main()
