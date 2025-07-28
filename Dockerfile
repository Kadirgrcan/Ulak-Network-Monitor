# Python'ın resmi hafif bir görüntüsünü temel al
FROM python:3.9-slim-buster

# Çalışma dizinini ayarla
WORKDIR /app

# Debian Buster'ın arşivlenmiş depolarını kullanmak için kaynak listesini güncelle
# Güvenli Depoları da ekle
# set -ex: Her komutun çıktısını gösterir ve herhangi bir hata durumunda derlemeyi durdurur.
RUN set -ex && \
    sed -i 's|deb.debian.org|archive.debian.org|g' /etc/apt/sources.list && \
    sed -i 's|security.debian.org|archive.debian.org/debian-security|g' /etc/apt/sources.list

# Sistem bağımlılıkları için snmp istemcisini, ping ve traceroute araçlarını yükle
# dnsutils paketi, nslookup gibi DNS araçlarını sağlar, ağ sorun giderme için faydalıdır.
# set -ex: Her komutun çıktısını gösterir ve herhangi bir hata durumunda derlemeyi durdurur.
RUN set -ex && \
    apt-get update && \
    apt-get install -yqq snmp net-tools iputils-ping traceroute dnsutils && \
    rm -rf /var/lib/apt/lists/*

# Yüklenen komutların PATH'te olup olmadığını kontrol et (Derleme zamanı kontrolü)
RUN which ping || echo "WARNING: ping command not found after install!"
RUN which traceroute || echo "WARNING: traceroute command not found after install!"
RUN which snmpwalk || echo "WARNING: snmpwalk command not found after install!"
RUN which snmpget || echo "WARNING: snmpget command not found after install!"

# Python bağımlılıklarını kopyala
COPY requirements.txt .

# Pip'i güncelleyin ve pysnmp ile ilgili tüm paketleri kaldırıp yeniden yükleyin
# Bu, pyasn1 hatasını gidermek için kritik bir adımdır.
# set -ex: Her komutun çıktısını gösterir ve herhangi bir hata durumunda derlemeyi durdurur.
RUN set -ex && \
    pip install --upgrade pip && \
    pip uninstall -y pysnmp pyasn1 pyasn1-modules pysmi pysnmp-mibs || true && \
    pip install --no-cache-dir pyasn1==0.6.1 pyasn1-modules==0.4.2 && \
    pip install --no-cache-dir -r requirements.txt

# Veritabanı kalıcılığı için 'data' klasörünü oluştur
RUN mkdir -p data

# Tüm uygulama kaynak kodunu kopyala (app.py, db.py, routes.py, templates klasörü vb.)
COPY . .

# Flask uygulamasının çalışacağı portu belirt
EXPOSE 5000

# Uygulamayı başlatmak için komut
# Gunicorn ile Flask uygulamasını başlat
# app.py dosyasındaki 'app' objesini Gunicorn'a iletiyoruz.
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--timeout", "120", "app:app"]
