import time
import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import re
import threading
import os
from fpdf import FPDF

class IDS:
    def __init__(self):
        # Alarm ve uyarıları saklamak için listeler
        self.alerts = []
        self.packet_counts = defaultdict(int)
        self.ip_counts = defaultdict(int)
        
        # Zaman penceresi (saniye)
        self.time_window = 5
        
        # Eşik değerleri
        self.port_scan_threshold = 15  # 5 saniye içinde 15'ten fazla port denemesi
        self.syn_flood_threshold = 25  # 5 saniye içinde 25'ten fazla SYN paketi
        self.icmp_flood_threshold = 10  # 5 saniye içinde 10'dan fazla ICMP paketi
        self.dos_threshold = 1000      # Genel DoS eşiği
        
        # İzleme için veri yapıları
        self.port_scan_tracker = defaultdict(list)  # {ip: [(timestamp, port), ...]}
        self.syn_flood_tracker = defaultdict(list)  # {ip: [timestamps, ...]}
        self.icmp_flood_tracker = defaultdict(list)  # {ip: [timestamps, ...]}
        
        # Çalışma durumu
        self.running = False
        
        # Şüpheli paket kalıpları
        self.suspicious_patterns = [
            rb"(?i)\x73\x65\x6C\x65\x63\x74.{0,10}\x66\x72\x6F\x6D",  # SQL injection
            rb"(?i)<script>",  # XSS
            rb"(?i)\x2F\x2E\x2E\x2F",  # Path traversal
            rb"(?i)\x65\x78\x65\x63\x28.*?\x29",  # Command execution - parantez kapatıldı
            rb"(?i)malware",  # Malware
            rb"(?i)eval\(.*?\)",  # Eval fonksiyonu - parantez kapatıldı
        ]
    
    def clean_old_entries(self, current_time):
        """Zaman penceresinden daha eski kayıtları temizler"""
        # Port tarama izleyicisini temizle
        for ip in list(self.port_scan_tracker.keys()):
            self.port_scan_tracker[ip] = [(ts, port) for ts, port in self.port_scan_tracker[ip] 
                                         if current_time - ts <= self.time_window]
            if not self.port_scan_tracker[ip]:
                del self.port_scan_tracker[ip]
        
        # SYN flood izleyicisini temizle
        for ip in list(self.syn_flood_tracker.keys()):
            self.syn_flood_tracker[ip] = [ts for ts in self.syn_flood_tracker[ip] 
                                         if current_time - ts <= self.time_window]
            if not self.syn_flood_tracker[ip]:
                del self.syn_flood_tracker[ip]
        
        # ICMP flood izleyicisini temizle
        for ip in list(self.icmp_flood_tracker.keys()):
            self.icmp_flood_tracker[ip] = [ts for ts in self.icmp_flood_tracker[ip] 
                                          if current_time - ts <= self.time_window]
            if not self.icmp_flood_tracker[ip]:
                del self.icmp_flood_tracker[ip]
    
    def check_port_scan(self, ip, port, current_time):
        """Port tarama kontrolü yapar"""
        self.port_scan_tracker[ip].append((current_time, port))
        
        # Son time_window içindeki benzersiz port sayısını kontrol et
        recent_ports = set(port for ts, port in self.port_scan_tracker[ip] 
                          if current_time - ts <= self.time_window)
        
        if len(recent_ports) > self.port_scan_threshold:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert_msg = f"[{timestamp}] ALARM: Port Tarama Tespiti - {ip} adresinden {len(recent_ports)} farklı porta erişim denemesi"
            if alert_msg not in self.alerts:
                self.alerts.append(alert_msg)
                print(alert_msg)
            return True
        return False
    
    def check_syn_flood(self, ip, current_time):
        """SYN flood kontrolü yapar"""
        self.syn_flood_tracker[ip].append(current_time)
        
        # Son time_window içindeki SYN paketi sayısını kontrol et
        recent_syns = len([ts for ts in self.syn_flood_tracker[ip] 
                          if current_time - ts <= self.time_window])
        
        if recent_syns > self.syn_flood_threshold:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert_msg = f"[{timestamp}] ALARM: DoS/SYN Flood Tespiti - {ip} adresinden {recent_syns} SYN paketi"
            if alert_msg not in self.alerts:
                self.alerts.append(alert_msg)
                print(alert_msg)
            return True
        return False
    
    def check_icmp_flood(self, ip, current_time):
        """ICMP flood kontrolü yapar"""
        self.icmp_flood_tracker[ip].append(current_time)
        
        # Son time_window içindeki ICMP paketi sayısını kontrol et
        recent_icmps = len([ts for ts in self.icmp_flood_tracker[ip] 
                           if current_time - ts <= self.time_window])
        
        if recent_icmps > self.icmp_flood_threshold:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert_msg = f"[{timestamp}] ALARM: ICMP Flood Tespiti - {ip} adresinden {recent_icmps} ICMP paketi"
            if alert_msg not in self.alerts:
                self.alerts.append(alert_msg)
                print(alert_msg)
            return True
        return False
    
    def check_pattern(self, packet):
        """Paket içeriğinde şüpheli pattern kontrolü yapar"""
        if Raw in packet and IP in packet:
            payload = bytes(packet[Raw].load)
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            for pattern in self.suspicious_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    alert_msg = f"[{timestamp}] ALARM: Şüpheli İçerik Tespiti - Kaynak: {src_ip}, Hedef: {dst_ip}"
                    if alert_msg not in self.alerts:
                        self.alerts.append(alert_msg)
                        print(alert_msg)
                    return True
        return False
    
    def analyze_packet(self, packet):
        """Paketleri analiz eder ve şüpheli aktiviteleri tespit eder"""
        if not self.running:
            return
            
        current_time = time.time()
        
        # Eski kayıtları temizle
        self.clean_old_entries(current_time)
        
        # IP paketi kontrolü
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.ip_counts[src_ip] += 1
            
            # TCP paketi kontrolü
            if TCP in packet:
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # Port tarama kontrolü
                self.check_port_scan(src_ip, dst_port, current_time)
                
                # SYN flood kontrolü (SYN bayrağı açık, ACK kapalı)
                if flags & 0x02 and not flags & 0x10:
                    self.check_syn_flood(src_ip, current_time)
                
                # Şüpheli portlar kontrolü
                suspicious_ports = [21, 22, 23, 25, 53, 445, 1433, 3306, 3389]
                if dst_port in suspicious_ports:
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    alert_msg = f"[{timestamp}] UYARI: {src_ip} adresinden hassas porta ({dst_port}) bağlantı girişimi"
                    if alert_msg not in self.alerts:
                        self.alerts.append(alert_msg)
                        print(alert_msg)
            
            # ICMP paketi kontrolü
            elif ICMP in packet:
                self.check_icmp_flood(src_ip, current_time)
            
            # Paket içeriğinde şüpheli kalıplar kontrolü
            self.check_pattern(packet)
            
            # DoS tespiti (tek IP'den çok fazla paket)
            if self.ip_counts[src_ip] > self.dos_threshold:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                alert_msg = f"[{timestamp}] ALARM: Olası DoS saldırısı! Kaynak: {src_ip}"
                if alert_msg not in self.alerts:
                    self.alerts.append(alert_msg)
                    print(alert_msg)
    
    def generate_report(self):
        """Tespit edilen alarmlar için PDF raporu oluşturur"""
        if not self.alerts:
            print("Kaydedilecek alarm bulunamadı.")
            return None
            
        pdf = FPDF()
        pdf.add_page()
        
        # Başlık
        pdf.set_font("Arial", "B", 16)
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pdf.cell(0, 10, f"Blue Network IDS Raporu - {current_time}", 0, 1, "C")
        pdf.ln(10)
        
        # Alarm sayısı
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, f"Toplam Alarm Sayisi: {len(self.alerts)}", 0, 1)
        pdf.ln(5)
        
        # Alarmlar
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Tespit Edilen Alarmlar:", 0, 1)
        pdf.set_font("Arial", "", 11)
        
        for alert in self.alerts:
            pdf.multi_cell(0, 7, alert)
            pdf.ln(3)
        
        # İstatistikler
        pdf.ln(10)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Ag Istatistikleri:", 0, 1)
        pdf.set_font("Arial", "", 11)
        
        # En aktif IP'ler
        pdf.cell(0, 7, "En Aktif IP Adresleri:", 0, 1)
        sorted_ips = sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for ip, count in sorted_ips:
            pdf.cell(0, 7, f"{ip}: {count} paket", 0, 1)
        
        # Raporu kaydet
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
            
        filename = f"{reports_dir}/ids_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf.output(filename)
        print(f"\nRapor kaydedildi: {filename}")
        return filename
    
    def timeout_handler(self, timeout_seconds):
        """Belirtilen süre sonunda çalışmayı durdurur"""
        time.sleep(timeout_seconds)
        self.running = False
        print("\nZaman asimi: IDS calisma suresini tamamladi.")
        
    def start(self, interface=None, timeout_seconds=300):  # 5 dakika = 300 saniye
        try:
            # Timeout için thread başlat
            timeout_thread = threading.Thread(target=self.timeout_handler, args=(timeout_seconds,))
            timeout_thread.daemon = True
            timeout_thread.start()
            
            # Ağ trafiğini dinlemeye başla
            print("IDS baslatiliyor...")
            print(f"Calisma suresi: {timeout_seconds} saniye")
            print("Ag trafigi izleniyor, cikmak icin Ctrl+C tuslarina basin...\n")
            
            self.running = True
            sniff(prn=self.analyze_packet, store=0, stop_filter=lambda p: not self.running, iface=interface)
            
        except KeyboardInterrupt:
            print("\nKullanici tarafindan durduruldu.")
        except Exception as e:
            print(f"\nHata: {e}")
        finally:
            print("IDS durduruldu. Rapor olusturuluyor...")
            self.generate_report()

# Ana program
if __name__ == "__main__":
    ids = IDS()
    ids.start()