
### BLUE NETWORK

Bu proje, ağ güvenliği ve izleme için geliştirilmiş bir araç setidir. İki ana bileşenden oluşur: Ağ İzleme (Network Monitoring) ve Saldırı Tespit Sistemi (IDS).

## Özellikler
### Ağ İzleme Aracı
- Otomatik Ağ Taraması: Yerel ağdaki tüm aktif cihazları tespit eder
- Cihaz Bilgileri: IP adresi, hostname, MAC adresi ve cihaz tipi bilgilerini gösterir
- Cihaz Tipi Tespiti: Hostname ve MAC adresine göre cihaz tipini tahmin eder
- Çoklu İş Parçacığı: Hızlı tarama için paralel işlem kullanır
### Saldırı Tespit Sistemi (IDS)
- Gerçek Zamanlı Paket Analizi: Scapy kütüphanesi ile ağ paketlerini yakalar ve analiz eder
- Zaman Penceresi Tabanlı Analiz: Son 5 saniye içindeki şüpheli aktiviteleri izler
- Otomatik Raporlama: Tespit edilen alarmları PDF formatında raporlar
- Belirli Süre Çalışma: Varsayılan olarak 5 dakika çalışır ve otomatik olarak durur Tespit Edilen Saldırı Türleri
- Port tarama saldırıları
- SYN flood saldırıları
- ICMP flood saldırıları
- DoS saldırıları
- Şüpheli içerik tespiti (SQL injection, XSS, path traversal, komut çalıştırma)
- Hassas portlara bağlantı girişimleri
## Kullanım
Ana menüden istediğiniz aracı seçebilirsiniz:

```
python main.py
```
Ya da araçları doğrudan çalıştırabilirsiniz:

```
# Ağ İzleme Aracı
python network_monitor.py

# Saldırı Tespit Sistemi
python ids.py
```
## Gereksinimler
- Python 3.x
- Scapy ( pip install scapy )
- FPDF ( pip install fpdf )
- PrettyTable ( pip install prettytable )

## Kurulum
```
# Gerekli kütüphaneleri yükleyin
pip install scapy fpdf prettytable
```
## Önemli Notlar
- IDS uygulamasının düzgün çalışabilmesi için yönetici (admin) haklarıyla çalıştırılması gereklidir.
- IDS, varsayılan olarak 5 dakika çalışır ve sonra otomatik olarak durur.
- Raporlar reports klasörüne kaydedilir.
- Ağ İzleme aracı, yerel ağınızdaki tüm cihazları tespit etmek için ping ve ARP sorgularını kullanır.
## Proje Yapısı
- main.py : Ana menü ve program başlangıç noktası
- network_monitor.py : Ağ izleme ve cihaz tespit aracı
- ids.py : Saldırı Tespit Sistemi
- reports/ : Oluşturulan PDF raporlarının saklandığı klasör
