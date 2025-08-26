import os
import sys
import subprocess

def clear_screen():
    """Ekranı temizler"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Uygulama başlığını gösterir"""
    clear_screen()
    print("=" * 70)
    print("\t\tBLUE NETWORK ARAÇLARI")
    print("=" * 70)

def print_menu():
    """Ana menüyü gösterir"""
    print("\nLütfen bir seçenek seçin:")
    print("1. Ağ İzleme (Network Monitoring)")
    print("2. Saldırı Tespit Sistemi (IDS)")
    print("3. Çıkış")

def run_network_monitor():
    """Ağ izleme uygulamasını çalıştırır"""
    clear_screen()
    print("Ağ İzleme uygulaması başlatılıyor...\n")
    try:
        # Python yorumlayıcısı ile network_monitor.py dosyasını çalıştır
        subprocess.call([sys.executable, "network_monitor.py"])
    except Exception as e:
        print(f"Hata: {e}")
    input("\nAna menüye dönmek için Enter tuşuna basın...")

def run_ids():
    """IDS uygulamasını çalıştırır"""
    clear_screen()
    print("Saldırı Tespit Sistemi (IDS) başlatılıyor...\n")
    print("Not: Bu uygulama yönetici haklarıyla çalıştırılmalıdır.")
    print("IDS 10 dakika çalışacak, sonra rapor oluşturup tekrar başlayacak.")
    print("Çıkmak için Ctrl+C tuşlarına basın.\n")
    try:
        # Python yorumlayıcısı ile ids.py dosyasını çalıştır
        subprocess.call([sys.executable, "ids.py"])
    except Exception as e:
        print(f"Hata: {e}")
    input("\nAna menüye dönmek için Enter tuşuna basın...")

def main():
    """Ana program döngüsü"""
    while True:
        print_header()
        print_menu()
        
        choice = input("\nSeçiminiz (1-3): ")
        
        if choice == "1":
            run_network_monitor()
        elif choice == "2":
            run_ids()
        elif choice == "3":
            print("\nProgram sonlandırılıyor...")
            sys.exit(0)
        else:
            input("\nGeçersiz seçim! Devam etmek için Enter tuşuna basın...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram kullanıcı tarafından sonlandırıldı.")
    except Exception as e:
        print(f"\nBir hata oluştu: {e}")
        input("\nÇıkmak için Enter tuşuna basın...")