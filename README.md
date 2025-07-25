# Ulak Network Monitor

## Proje Hakkında

Bu proje, Ulak Haberleşme'deki 20 günlük zorunlu stajım kapsamında, ağ altyapıları bölümünde geliştirilmiş, Python ve Flask kullanılarak oluşturulmuş, Dockerize edilmiş basit ama etkili bir ağ izleme platformudur. Temel amacı, ağ cihazlarının anlık sağlık durumlarını (CPU, RAM, Disk kullanımı, Ağ Trafiği) izlemek ve ağ sorun giderme süreçlerini kolaylaştırmak için temel ağ araçlarını (ping, port tarama, traceroute) tek bir web arayüzünde birleştirmektir. Uygulama, bulut ortamlarında (özellikle AWS EC2) kolayca dağıtılabilir ve yönetilebilir olacak şekilde tasarlanmıştır.

## Özellikler

### Ana Kontrol Paneli

Sisteme kayıtlı toplam cihaz sayısını, aktif uyarıların anlık sayısını ve ağın genel sağlık durumunu (Normal/Uyarı) özetleyen merkezi bir bakış sunar.

### IP Ping Testi

-   **Teknik Detay:** ICMP (Internet Control Message Protocol) paketleri göndererek hedef IP adresinin erişilebilirliğini ve ağ gecikmesini (latency) ölçer.
    
-   **Metrikler:** Ortalama gecikme (ms), jitter (gecikme dalgalanması) ve paket kaybı yüzdesi gibi kritik performans metriklerini sağlar.
    
-   **Uygulama:** Python'ın `subprocess` modülü aracılığıyla sistemdeki `ping` komutunu çalıştırır ve çıktısını ayrıştırır.
    

### Port Tarama

-   **Teknik Detay:** Belirtilen bir IP adresindeki belirli TCP portlarına bağlantı kurmaya çalışarak portun açık (dinlemede), kapalı veya filtrelenmiş olup olmadığını kontrol eder.
    
-   **Uygulama:** Python'ın `socket` modülü kullanılarak doğrudan TCP bağlantı denemeleri yapılır. Her port için bağlantı durumu, gecikme süresi ve bilinen servis adı (varsa) gösterilir.
    

### Traceroute

-   **Teknik Detay:** Hedef IP adresine giden ağ yolunu (hop'lar) ve her bir atlamadaki gecikmeleri (TTL - Time To Live değerini artırarak) izler. ICMP "Time Exceeded" mesajlarını kullanarak her router'ı tespit eder.
    
-   **Görselleştirme:** Elde edilen IP adreslerinin coğrafi konum bilgileri (ip-api.com API'si aracılığıyla) toplanır ve Leaflet.js kütüphanesi kullanılarak interaktif bir harita üzerinde gösterilir.
    
-   **Uygulama:** `subprocess` modülü ile sistemdeki `traceroute` komutu çalıştırılır ve çıktısı ayrıştırılır.
    

### SNMP İzleme

-   **Teknik Detay:** SNMP (Simple Network Management Protocol) kullanarak ağ cihazlarından (router, switch, sunucu vb.) detaylı operasyonel veriler çeker.
    
-   **Çekilen Veriler:**
    
    -   **CPU Kullanımı:** `hrDeviceProcessorLoad` (OID: `1.3.6.1.2.1.25.3.3.1.2`) veya UCD-SNMP-MIB'den CPU yük ortalaması (OID: `1.3.6.1.4.1.2021.10.1.3.1`) gibi OID'ler kullanılır.
        
    -   **RAM Kullanımı:** `hrMemorySize` (OID: `1.3.6.1.2.1.25.2.2.0`) ile toplam RAM ve `hrStorageTable` (OID: `1.3.6.1.2.1.25.2.3.1`) ile kullanılan fiziksel bellek miktarı alınır.
        
    -   **Disk Kullanımı:** `hrStorageTable` üzerinden sabit disk bölümlerinin toplam ve kullanılan alanları (GB cinsinden) ve doluluk yüzdeleri hesaplanır.
        
    -   **Ağ Arayüz Trafiği:** `ifTable` (OID: `1.3.6.1.2.1.2.2.1`) üzerinden arayüz açıklamaları (`ifDescr`), hız (`ifSpeed`), fiziksel adres (`ifPhysAddress`), operasyonel durum (`ifOperStatus`), gelen (`ifInOctets`) ve giden (`ifOutOctets`) baytlar gibi bilgiler toplanır.
        
    -   **Sistem Bilgisi:** `sysDescr`, `sysName`, `sysLocation` gibi standart sistem OID'leri ile cihaz hakkında genel bilgiler alınır.
        
    -   **Çalışma Süresi (Uptime):** Cihazın ne kadar süredir çalıştığı (`sysUpTime`) bilgisi alınır.
        
    -   **TCP Bağlantıları:** `tcpConnState` (OID: `1.3.6.1.2.1.6.13.1.1`) OID'si taranarak aktif (established) TCP bağlantı sayısı tespit edilir.
        
-   **Uygulama:** Python'ın `subprocess` modülü ile `snmpget` ve `snmpwalk` komutları çalıştırılır, ham çıktılar düzenli ifadeler (`re` modülü) ve özel ayrıştırma fonksiyonları ile işlenir.
    

### Gerçek Zamanlı SpeedTest

-   **Teknik Detay:** SNMP aracılığıyla belirli bir ağ arayüzünün `ifInOctets` ve `ifOutOctets` sayaçlarını düzenli aralıklarla sorgular. İki ardışık okuma arasındaki bayt farkını geçen süreye bölerek anlık indirme ve yükleme hızlarını (Mbps cinsinden) hesaplar. Counter64 OID'leri kullanılarak büyük trafik değerleri doğru şekilde işlenir.
    
-   **Görselleştirme:** Chart.js kütüphanesi kullanılarak indirme ve yükleme hızları canlı olarak bir çizgi grafikte gösterilir. Zaman ekseni için moment.js ve chartjs-adapter-moment adaptörü kullanılır.
    
-   **Uygulama:** AJAX çağrıları ile Flask backend'indeki `/get_speed_data` endpoint'ine istek atılır ve dönen veriler JavaScript ile işlenerek grafik güncellenir.
    

### Cihaz Yönetimi

İzlenecek ağ cihazlarını (IP adresi, SNMP Community String, CPU, RAM, Disk için özel eşik değerleri ile birlikte) veritabanına ekleme, mevcut cihaz bilgilerini düzenleme ve silme yeteneği sunar.

### Uyarı Yönetimi

-   **Teknik Detay:** Cihazlara özel olarak belirlenen CPU, RAM ve Disk kullanım eşik değerleri periyodik olarak kontrol edilir.
    
-   **Mekanizma:** APScheduler kütüphanesi kullanılarak arka planda belirli aralıklarla (örn: her 5 dakikada bir) SNMP verileri çekilir ve eşik değerleri aşılırsa veya cihazdan veri alınamazsa otomatik olarak uyarılar oluşturulur. Eşik değerlerinin altına düşüldüğünde ise aktif uyarılar otomatik olarak çözümlenir.
    

## Kurulum ve Çalıştırma

### Yerel Kurulum

1.  **Depoyu Klonlayın:**
    
    ```
    git clone https://github.com/Kadirgrcan/ulak-monitoring-app.git
    cd ulak-monitoring-app
    
    ```
    
2.  **Sanal Ortam Oluşturun ve Aktif Edin:**
    
    ```
    python3 -m venv venv
    source venv/bin/activate  # Linux/macOS
    # veya
    # venv\Scripts\activate   # Windows
    
    ```
    
3.  **Python Bağımlılıklarını Kurun:**
    
    ```
    pip install -r requirements.txt
    
    ```
    
4.  Sistem Bağımlılıklarını Kurun:
    
    snmpget, snmpwalk, ping, traceroute gibi komutların sisteminizde kurulu olduğundan emin olun. Bu araçlar, uygulamanın ağ sorgularını gerçekleştirmesi için zorunludur.
    
    -   **Debian/Ubuntu:** `sudo apt-get update && sudo apt-get install -y net-snmp net-snmp-utils iputils-ping traceroute dnsutils`
        
    -   **CentOS/RHEL:** `sudo yum install -y net-snmp net-snmp-utils iputils-utils traceroute bind-utils`
        
    -   **Windows:** Windows Subsystem for Linux (WSL) kullanılması veya ilgili araçların manuel olarak kurulması önerilir.
        
5.  **Uygulamayı Çalıştırın:**
    
    ```
    flask run --host=0.0.0.0 --port=5000
    
    ```
    
    Tarayıcınızda `http://127.0.0.1:5000` adresine gidin.
    

### Docker ile Kurulum ve Çalıştırma (Önerilen)

Bu yöntem, tüm bağımlılıkları içeren taşınabilir ve izole bir ortam sağlar.

1.  **Depoyu Klonlayın:**
    
    ```
    git clone https://github.com/Kadirgrcan/ulak-monitoring-app.git
    cd ulak-monitoring-app
    
    ```
    
2.  Docker İmajını Oluşturun:
    
    Bu komut, Dockerfile içindeki talimatları kullanarak uygulamanız için bir Docker imajı oluşturur. Bu işlem, gerekli tüm sistem ve Python bağımlılıklarını kurar.
    
    ```
    docker build -t ulak-monitoring-app .
    
    ```
    
3.  Docker Konteynerini Çalıştırın:
    
    Bu komut, oluşturulan Docker imajından yeni bir konteyner başlatır. -d ile arka planda çalışır, -p 5000:5000 ile host makinenin 5000 portunu konteynerin 5000 portuna yönlendirir ve --name ile konteynere kolay erişim için bir isim verir.
    
    ```
    docker run -d -p 5000:5000 --name ulak-monitoring-container ulak-monitoring-app
    
    ```
    
    Uygulama arka planda çalışacaktır.
    
4.  Uygulamaya Erişin:
    
    Tarayıcınızda http://localhost:5000 adresine gidin.
    

### AWS EC2 Üzerinde Dağıtım

1.  **EC2 Instance Hazırlığı:**
    
    -   Bir AWS EC2 instance başlatın (örneğin Ubuntu 20.04 LTS veya Amazon Linux 2 AMI'si önerilir).
        
    -   EC2 instance'ınızın güvenlik grubunda (Security Group) SSH için 22. port ve uygulamanız için 5000. porttan gelen TCP trafiğine izin veren kurallar ekleyin. Kaynak IP'yi `0.0.0.0/0` (her yerden erişim) olarak ayarlayabilir veya daha güvenli bir şekilde sadece kendi IP adresinizi belirleyebilirsiniz.
        
2.  **EC2 instance'ınıza SSH ile bağlanın ve Docker'ı kurun:**
    
    ```
    sudo apt-get update # veya sudo yum update
    sudo apt-get install -y docker.io # veya sudo yum install -y docker
    sudo systemctl start docker
    sudo systemctl enable docker
    sudo usermod -aG docker ec2-user # 'ec2-user' yerine kendi kullanıcı adınız olabilir (örn: ubuntu)
    # Değişikliklerin etkili olması için SSH oturumundan çıkış yapıp tekrar giriş yapın veya 'newgrp docker' komutunu çalıştırın.
    
    ```
    
3.  Kodu EC2'ye Klonlayın:
    
    EC2 instance'ınızda proje klasörünüze gidin ve GitHub deponuzu klonlayın:
    
    ```
    git clone https://github.com/Kadirgrcan/ulak-monitoring-app.git
    cd ulak-monitoring-app
    
    ```
    
4.  Docker İmajını Oluşturun ve Çalıştırın:
    
    Yerel Docker kurulum adımlarının aynısını uygulayın:
    
    ```
    docker build -t ulak-monitoring-app .
    docker run -d -p 5000:5000 --name ulak-monitoring-container ulak-monitoring-app
    
    ```
    
5.  Uygulamaya Erişin:
    
    Tarayıcınızda http://<EC2_INSTANCE_PUBLIC_IP_ADRESI>:5000 adresine giderek uygulamanıza erişebilirsiniz.
    

## Kullanım

Uygulama arayüzü oldukça sezgiseldir ve Bootstrap ile modern bir tasarıma sahiptir. Navigasyon menüsünü ve ana sayfadaki özellik kutucuklarını kullanarak farklı araçlara ve izleme sayfalarına kolayca erişebilirsiniz:

-   **Ana Sayfa:** Ağınızın genel durumu, son tarama kayıtları ve kayıtlı cihazların özetini sunar.
    
-   **Cihazlar:** SNMP ile izlenecek cihazları (IP adresi, Community String, CPU/RAM/Disk eşikleri) ekleyebilir, düzenleyebilir veya silebilirsiniz.
    
-   **Uyarılar:** Cihazların eşik değerlerini aştığında veya veri alınamadığında oluşan aktif uyarıları ve geçmiş uyarı kayıtlarını görüntüler.
    
-   **Araçlar (Dropdown Menü):**
    
    -   **Ping:** Bir IP adresine ICMP ping testleri yaparak ağ bağlantısını ve gecikmeyi ölçer.
        
    -   **Port Tarama:** Belirtilen bir IP adresindeki belirli TCP portlarının durumunu (açık/kapalı) kontrol eder.
        
    -   **Traceroute:** Bir hedefe giden ağ yolunu ve her atlamadaki gecikmeleri görsel olarak harita üzerinde sunar.
        
    -   **SNMP Sorgu:** Kayıtlı cihazlardan CPU, RAM, Disk, ağ arayüzleri, sistem bilgisi, çalışma süresi ve TCP bağlantıları gibi kapsamlı SNMP verilerini çeker ve görüntüler.
        
    -   **SpeedTest:** Seçilen bir ağ arayüzünün anlık indirme ve yükleme hızlarını gerçek zamanlı bir grafik üzerinde canlı olarak izlemenizi sağlar.
        

## Proje Yapısı

```
.
├── app.py                  # Flask ana uygulama dosyası, rotaları ve arka plan görevlerini yönetir.
├── db.py                   # SQLite veritabanı bağlantısı ve CRUD (Oluşturma, Okuma, Güncelleme, Silme) işlemleri.
├── routes.py               # Flask rotalarını tanımlar ve HTTP isteklerini işler, SNMP yardımcı fonksiyonlarını içerir.
├── requirements.txt        # Python bağımlılıkları listesi (pip install -r).
├── Dockerfile              # Docker imajını oluşturmak için talimatlar, sistem bağımlılıklarını ve Python paketlerini kurar.
├── templates/              # Flask'ın render_template() fonksiyonu tarafından kullanılan HTML şablonları.
│   ├── index.html          # Ana kontrol paneli sayfası.
│   ├── ping.html           # Ping testi formu.
│   ├── ping_result.html    # Ping testi sonuçları.
│   ├── portscan.html       # Port tarama formu.
│   ├── portscan_result.html# Port tarama sonuçları.
│   ├── traceroute.html     # Traceroute formu.
│   ├── traceroute_result.html # Traceroute sonuçları ve harita.
│   ├── snmp_form.html      # SNMP sorgu formu.
│   ├── snmp_result.html    # SNMP sorgu sonuçları.
│   ├── speedtest.html      # Gerçek zamanlı SpeedTest sayfası (Chart.js entegrasyonlu).
│   ├── cihazlar.html       # Cihaz yönetimi (ekleme/düzenleme/silme) sayfası.
│   ├── alerts.html         # Aktif uyarıları gösteren sayfa.
│   └── alerts_history.html # Tüm uyarıların geçmişini gösteren sayfa.
└── data/                   # Uygulama tarafından oluşturulan SQLite veritabanı dosyası (tarama.db) için dizin.

```

## Katkıda Bulunma

Geliştirmeye katkıda bulunmak isterseniz, lütfen bir Pull Request (Çekme İsteği) gönderin.

## İletişim

Sorularınız veya geri bildirimleriniz için bana aşağıdaki kanallardan ulaşabilirsiniz:

-   Kadir Gürcan - kadirgurcan@ogr.eskisehir.edu.tr
    
-   [GitHub Profilim](https://github.com/Kadirgrcan "null") <!-- Lütfen burayı kendi GitHub profil linkinizle değiştirin -->
    
-   [LinkedIn Profilim](https://www.google.com/search?q=https://www.linkedin.com/in/kadir-g%C3%BCrcan-81a1a1204/ "null") <!-- Lütfen burayı kendi LinkedIn profil linkinizle değiştirin -->
    

**Staj Projesi Detayları:** Bu proje, Ulak Haberleşme'deki 20 günlük zorunlu stajım kapsamında, Ağ Altyapıları bölümünde geliştirilmiştir. Proje, staj süresince edindiğim bilgi ve becerileri pekiştirmeyi ve pratik bir ağ izleme çözümü sunmayı amaçlamaktadır.
