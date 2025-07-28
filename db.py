import sqlite3
import threading
from datetime import datetime

db_lock = threading.Lock()
DATABASE = 'data/tarama.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # Sütunlara isimleriyle erişimi sağlar
    return conn

def create_tables():
    """Uygulama için gerekli veritabanı tablolarını oluşturur."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS kayitlar (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            durum TEXT,
            gecikme_ms REAL,
            tarih_saat TEXT
        )
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS cihazlar (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            isim TEXT,
            ip TEXT,
            community TEXT,
            cpu_threshold REAL DEFAULT 80.0,  -- Yeni sütun: CPU eşiği
            ram_threshold REAL DEFAULT 80.0,   -- Yeni sütun: RAM eşiği
            disk_threshold REAL DEFAULT 90.0   -- Yeni sütun: Disk eşiği
        )
        """)
        # Mevcut bir veritabanı varsa ve sütunlar yoksa eklemek için ALTER TABLE
        # Bu kısım sadece mevcut veritabanı şemasını güncellemek için kullanılır.
        # Eğer data/tarama.db dosyasını silip baştan başlayacaksanız bu kısmı kullanmanıza gerek yoktur.
        try:
            cursor.execute("ALTER TABLE cihazlar ADD COLUMN cpu_threshold REAL DEFAULT 80.0")
        except sqlite3.OperationalError:
            pass # Sütun zaten varsa hata verme
        try:
            cursor.execute("ALTER TABLE cihazlar ADD COLUMN ram_threshold REAL DEFAULT 80.0")
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("ALTER TABLE cihazlar ADD COLUMN disk_threshold REAL DEFAULT 90.0")
        except sqlite3.OperationalError:
            pass

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER,
            device_name TEXT,
            ip TEXT,
            metric TEXT, -- Örn: CPU, RAM, Disk
            value REAL,
            threshold REAL,
            message TEXT,
            timestamp TEXT,
            status TEXT DEFAULT 'active' -- 'active', 'resolved'
        )
        """)
        conn.commit()
        conn.close()

def add_scan_record(ip, port, durum, gecikme_ms, tarih_saat):
    """Yeni bir tarama kaydını veritabanına ekler."""
    with db_lock:
        conn = get_db_connection()
        conn.execute("INSERT INTO kayitlar (ip, port, durum, gecikme_ms, tarih_saat) VALUES (?, ?, ?, ?, ?)",
                     (ip, port, durum, gecikme_ms, tarih_saat))
        conn.commit()
        conn.close()

def get_recent_scan_records(limit=10):
    """En son tarama kayıtlarını döndürür."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM kayitlar ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows

def clear_scan_records():
    """Tüm tarama kayıtlarını siler."""
    with db_lock:
        conn = get_db_connection()
        conn.execute("DELETE FROM kayitlar")
        conn.commit()
        conn.close()

def add_device(isim, ip, community, cpu_threshold=80.0, ram_threshold=80.0, disk_threshold=90.0):
    """Yeni bir cihazı veritabanına ekler."""
    with db_lock:
        conn = get_db_connection()
        conn.execute("INSERT INTO cihazlar (isim, ip, community, cpu_threshold, ram_threshold, disk_threshold) VALUES (?, ?, ?, ?, ?, ?)",
                     (isim, ip, community, cpu_threshold, ram_threshold, disk_threshold))
        conn.commit()
        conn.close()

def update_device(device_id, isim, ip, community, cpu_threshold, ram_threshold, disk_threshold):
    """Mevcut bir cihazın bilgilerini günceller."""
    with db_lock:
        conn = get_db_connection()
        conn.execute(
            "UPDATE cihazlar SET isim = ?, ip = ?, community = ?, cpu_threshold = ?, ram_threshold = ?, disk_threshold = ? WHERE id = ?",
            (isim, ip, community, cpu_threshold, ram_threshold, disk_threshold, device_id)
        )
        conn.commit()
        conn.close()

def get_all_devices():
    """Tüm kayıtlı cihazları döndürür."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM cihazlar")
        rows = cursor.fetchall()
        conn.close()
        return rows

def get_device_by_id(device_id):
    """Belirli bir cihazı ID'sine göre döndürür."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM cihazlar WHERE id = ?", (device_id,))
        device = cursor.fetchone()
        conn.close()
        return device

def delete_device(device_id):
    """Belirli bir cihazı ID'sine göre siler."""
    with db_lock:
        conn = get_db_connection()
        conn.execute("DELETE FROM cihazlar WHERE id = ?", (device_id,))
        conn.commit()
        conn.close()

def add_alert(device_id, device_name, ip, metric, value, threshold, message):
    """Yeni bir uyarı kaydını veritabanına ekler veya mevcut aktif uyarıyı günceller."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.execute(
            "SELECT id FROM alerts WHERE device_id = ? AND metric = ? AND status = 'active'",
            (device_id, metric)
        )
        existing_alert = cursor.fetchone()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if existing_alert:
            # Mevcut aktif uyarıyı güncelle
            conn.execute(
                "UPDATE alerts SET value = ?, threshold = ?, message = ?, timestamp = ? WHERE id = ?",
                (value, threshold, message, timestamp, existing_alert['id'])
            )
        else:
            # Yeni uyarı ekle
            conn.execute(
                "INSERT INTO alerts (device_id, device_name, ip, metric, value, threshold, message, timestamp, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (device_id, device_name, ip, metric, value, threshold, message, timestamp, 'active')
            )
        conn.commit()
        conn.close()

def get_active_alerts():
    """Aktif olan tüm uyarıları döndürür."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM alerts WHERE status = 'active' ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()
        return rows

def get_all_alerts():
    """Tüm uyarıları (aktif ve çözülmüş) döndürür."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()
        return rows

def get_active_alert_count():
    """Toplam aktif uyarı sayısını döndürür."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM alerts WHERE status = 'active'")
        count = cursor.fetchone()[0]
        conn.close()
        return count

def resolve_alert(alert_id):
    """Belirli bir uyarıyı 'resolved' olarak işaretler."""
    with db_lock:
        conn = get_db_connection()
        conn.execute("UPDATE alerts SET status = 'resolved' WHERE id = ?", (alert_id,))
        conn.commit()
        conn.close()

def check_and_resolve_alerts(device_id, metric, current_value, threshold):
    """Mevcut değer eşiğin altına düştüğünde aktif uyarıları çözümlemeye çalışır."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.execute(
            "SELECT id FROM alerts WHERE device_id = ? AND metric = ? AND status = 'active'",
            (device_id, metric)
        )
        active_alert = cursor.fetchone()
        if active_alert:
            # CPU/RAM için eşiğin %10 altında bir değerle normale dönmüşse çöz
            # Disk için eşiğin %5 altında bir değerle normale dönmüşse çöz
            if (metric == 'CPU' and current_value < threshold * 0.9) or \
               (metric == 'RAM' and current_value < threshold * 0.9) or \
               (metric == 'Disk' and current_value < threshold * 0.95): # Disk için biraz daha toleranslı olabiliriz
                 conn.execute("UPDATE alerts SET status = 'resolved' WHERE id = ?",(active_alert['id'],))
                 conn.commit()
        conn.close() # Bağlantıyı kapat

def get_total_device_count():
    """Toplam kayıtlı cihaz sayısını döndürür."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM cihazlar")
        count = cursor.fetchone()[0]
        conn.close()
        return count
