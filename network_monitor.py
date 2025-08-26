import socket
import ipaddress
import subprocess
import threading
import time
import platform
from datetime import datetime
from prettytable import PrettyTable

class NetworkMonitor:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.network = self.get_network()
        self.devices = []
        self.lock = threading.Lock()
        
    def get_local_ip(self):
        """Yerel IP adresini otomatik olarak alır"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Bu bağlantı gerçekten yapılmaz, sadece yerel IP'yi öğrenmek için kullanılır
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip
    
    def get_network(self):
        """IP adresinden ağ adresini belirler"""
        ip_parts = self.local_ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    def ping(self, ip):
        """Belirtilen IP adresine ping atar"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', '500', str(ip)]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    
    def get_hostname(self, ip):
        """IP adresinden hostname'i bulmaya çalışır (reverse lookup)"""
        try:
            hostname = socket.getfqdn(str(ip))
            if hostname != str(ip):
                return hostname
            else:
                # Alternatif yöntem dene
                hostname = socket.gethostbyaddr(str(ip))[0]
                return hostname
        except Exception:
            return "Bulunamadı"
    
    def get_mac(self, ip):
        """IP adresinden MAC adresini bulmaya çalışır (ARP ve ICMP kullanarak)"""
        # ICMP (ping) kullanarak ARP tablosunu güncelle
        try:
            # Önce ICMP echo request (ping) gönder
            subprocess.call(['ping', '-n', '1', '-w', '500', str(ip)], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Kısa bir bekleme süresi ekle (ARP tablosunun güncellenmesi için)
            time.sleep(0.5)
            
            # Şimdi ARP tablosunu sorgula
            if platform.system().lower() == 'windows':
                # ARP tablosunu sorgula
                output = subprocess.check_output("arp -a", shell=True).decode('utf-8')
                lines = output.strip().split('\n')
                
                # Tüm ARP tablosunu tara ve IP adresini bul
                for line in lines:
                    if str(ip) in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            mac = parts[1].replace('-', ':')
                            # Geçersiz MAC adreslerini filtrele
                            if mac != "00:00:00:00:00:00" and not mac.startswith("ff:ff:ff"):
                                print(f"MAC adresi bulundu: {ip} -> {mac}")
                                return mac
                    
                # Hedef IP için özel ARP sorgusu
                output = subprocess.check_output(f"arp -a {ip}", shell=True).decode('utf-8')
                lines = output.strip().split('\n')
                for line in lines:
                    if str(ip) in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            mac = parts[1].replace('-', ':')
                            if mac != "00:00:00:00:00:00" and not mac.startswith("ff:ff:ff"):
                                print(f"Özel ARP sorgusu ile MAC adresi bulundu: {ip} -> {mac}")
                                return mac
            else:  # Linux için
                output = subprocess.check_output(f"arp -n {ip}", shell=True).decode('utf-8')
                lines = output.strip().split('\n')
                for line in lines:
                    if str(ip) in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            mac = parts[2]
                            if mac != "00:00:00:00:00:00" and not mac.startswith("ff:ff:ff"):
                                return mac
            
            # Özel durumlar için MAC adresleri
            if str(ip).endswith('.1'):
                print(f"Router için varsayılan MAC adresi atanıyor: {ip}")
                return "00:00:00:00:00:01"  # Router için özel bir MAC adresi
                
        except Exception as e:
            print(f"MAC adresi alınırken hata: {e}")
            
            return "Bulunamadı"
    
    def guess_device_type(self, hostname, mac, ip):
        """Hostname, MAC adresi ve IP adresinden cihaz tipini tahmin etmeye çalışır"""
        # Özel IP kontrolü - Router tespiti
        if ip.endswith('.1') or ip.endswith('.254'):
            return "Router/Modem"
        
        hostname = hostname.lower() if hostname != "Bulunamadı" else ""
        
        # Hostname'e göre tahmin
        if "printer" in hostname or "yazici" in hostname or "print" in hostname:
            return "Yazıcı"
        elif "phone" in hostname or "telefon" in hostname or "mobile" in hostname:
            return "Telefon"
        elif "laptop" in hostname or "notebook" in hostname:
            return "Laptop"
        elif "desktop" in hostname or "pc" in hostname or "computer" in hostname:
            return "Bilgisayar"
        elif "router" in hostname or "modem" in hostname or "gateway" in hostname:
            return "Router/Modem"
        elif "cam" in hostname or "camera" in hostname:
            return "Kamera"
        elif "tv" in hostname or "television" in hostname:
            return "TV"
        
        # MAC adresine göre bazı üreticileri tanımla
        if mac != "Bulunamadı":
            mac_prefix = mac.upper().replace(':', '')[:6]
            vendors = {
                "FCFBFB": "Apple",
                "ACBC32": "Apple",
                "B8E856": "Apple",
                "1C36BB": "Apple",
                "3C2EFF": "Apple",
                "0050C2": "IEEE",
                "00E04C": "Realtek",
                "001A79": "SAMSUNG",
                "001632": "SAMSUNG",
                "0023D7": "SAMSUNG",
                "5C497D": "SAMSUNG",
                "B407F9": "SAMSUNG",
                "001C43": "SAMSUNG",
                "0019D2": "Intel",
                "001DE0": "Intel",
                "001E67": "Intel",
                "0022FA": "Intel",
                "0026C6": "Intel",
                "00E018": "ASUSTek",
                "000C6E": "ASUSTek",
                "001BFC": "ASUSTek",
                "485D60": "AzureWave",
                "002248": "Microsoft",
                "0025AE": "Microsoft",
                "00125A": "Microsoft",
                "00155D": "Microsoft",
                "985FD3": "Microsoft",
                "E894F6": "TP-Link",
                "D8490B": "HUAWEI",
                "00E0FC": "HUAWEI",
                "001E10": "HUAWEI",
                "002568": "HUAWEI",
                "001882": "HUAWEI"
            }
            
            for prefix, vendor in vendors.items():
                if mac_prefix.startswith(prefix):
                    if vendor == "Apple":
                        return "Apple Cihazı"
                    elif vendor == "SAMSUNG":
                        return "Samsung Cihazı"
                    elif vendor == "HUAWEI":
                        return "Huawei Cihazı"
                    elif vendor == "TP-Link":
                        return "TP-Link Cihazı"
                    elif vendor == "Microsoft":
                        return "Microsoft Cihazı"
                    else:
                        return f"{vendor} Cihazı"
    
        # Yerel bilgisayarı tespit et
        if ip == self.local_ip:
            return "Bu Bilgisayar"
        
        return "Bilinmeyen Cihaz"
    
    def scan_ip(self, ip):
        """Belirtilen IP'yi tarar ve aktifse bilgilerini toplar"""
        if self.ping(ip):
            print(f"Aktif cihaz bulundu: {ip}")
            hostname = self.get_hostname(ip)
            mac = self.get_mac(ip)
            device_type = self.guess_device_type(hostname, mac, str(ip))
            
            with self.lock:
                self.devices.append({
                    'ip': str(ip),
                    'hostname': hostname,
                    'mac': mac,
                    'type': device_type,
                    'status': 'Aktif'
                })
    
    def scan_network(self):
        """Ağdaki tüm IP'leri tarar"""
        print(f"Ağ taraması başlatılıyor: {self.network}")
        print(f"Yerel IP adresiniz: {self.local_ip}")
        print("Lütfen bekleyin, bu işlem birkaç dakika sürebilir...\n")
        
        start_time = time.time()
        threads = []
        
        # Tüm IP'leri tara
        for ip in ipaddress.IPv4Network(self.network):
            # Network adresi ve broadcast adresini atla
            if str(ip).endswith('.0') or str(ip).endswith('.255'):
                continue
                
            t = threading.Thread(target=self.scan_ip, args=(ip,))
            threads.append(t)
            t.start()
            
            # Thread sayısını sınırla
            if len(threads) >= 100:
                for thread in threads:
                    thread.join()
                threads = []
        
        # Kalan thread'lerin tamamlanmasını bekle
        for thread in threads:
            thread.join()
            
        end_time = time.time()
        scan_duration = end_time - start_time
        
        return scan_duration
    
    def display_results(self):
        """Tarama sonuçlarını tablo halinde gösterir"""
        if not self.devices:
            print("Ağda hiçbir aktif cihaz bulunamadı.")
            return
        
        # Sonuçları IP adresine göre sırala
        self.devices.sort(key=lambda x: socket.inet_aton(x['ip']))
        
        # Tablo oluştur
        table = PrettyTable()
        table.field_names = ["IP Adresi", "Hostname", "MAC Adresi", "Cihaz Tipi", "Durum"]
        
        for device in self.devices:
            table.add_row([
                device['ip'],
                device['hostname'],
                device['mac'],
                device['type'],
                device['status']
            ])
        
        print(table)
        print(f"\nToplam {len(self.devices)} aktif cihaz bulundu.")
    
    def run(self):
        """Ağ taramasını başlatır ve sonuçları gösterir"""
        print("=" * 70)
        print("\t\tAĞ İZLEME ARACI")
        print("=" * 70)
        print(f"Tarama Başlangıç Zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        duration = self.scan_network()
        
        print("\n" + "=" * 70)
        print(f"Tarama Tamamlandı! Süre: {duration:.2f} saniye")
        print("=" * 70 + "\n")
        
        self.display_results()

if __name__ == "__main__":
    try:
        monitor = NetworkMonitor()
        monitor.run()
        
        # Kullanıcının sonuçları görmesi için bekle
        input("\nÇıkmak için Enter tuşuna basın...")
    except KeyboardInterrupt:
        print("\nProgram kullanıcı tarafından sonlandırıldı.")
    except Exception as e:
        print(f"\nBir hata oluştu: {e}")
