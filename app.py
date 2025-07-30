import socket
import subprocess
import re
import requests
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, jsonify
import json 

from apscheduler.schedulers.background import BackgroundScheduler
import atexit # Uygulama kapanışında scheduler'ı durdurmak için

import db # db.py dosyasını import ediyoruz
import routes # routes.py dosyasını import ediyoruz (Rota tanımları burada)

app = Flask(__name__)

# Veritabanı tablolarını uygulamanın başlangıcında oluştur
# Bu satır, Gunicorn ile çalışırken de tabloların oluşturulmasını sağlar.
db.create_tables() 

# APScheduler'ı başlat
scheduler = BackgroundScheduler()

# SNMP OIDs (Ortak OID'ler burada tanımlandı)
OID_CPU_LOAD = "1.3.6.1.2.1.25.3.3.1.2" # hrDeviceProcessorLoad (Gauge32) - Some systems don't support this well.
# OID for UCD-SNMP-MIB for CPU Load Average (1, 5, 15 minutes) - More common on Linux
OID_CPU_LOAD_1MIN = "1.3.6.1.4.1.2021.10.1.3.1"
OID_CPU_LOAD_5MIN = "1.3.6.1.4.1.2021.10.1.3.2"
OID_CPU_LOAD_15MIN = "1.3.6.1.4.1.2021.10.1.3.3"

OID_HR_STORAGE_TABLE = "1.3.6.1.2.1.25.2.3.1"
OID_HR_STORAGE_TYPE = OID_HR_STORAGE_TABLE + ".2" # hrStorageType (OID)
OID_HR_STORAGE_ALLOCATION_UNITS = OID_HR_STORAGE_TABLE + ".4" # hrStorageAllocationUnits (INTEGER)
OID_HR_STORAGE_SIZE = OID_HR_STORAGE_TABLE + ".5" # hrStorageSize (INTEGER)
OID_HR_STORAGE_USED = OID_HR_STORAGE_TABLE + ".6" # hrStorageUsed (INTEGER)
OID_HR_STORAGE_DESCR = OID_HR_STORAGE_TABLE + ".3" # hrStorageDescr (STRING)
OID_MEMORY_SIZE = "1.3.6.1.2.1.25.2.2.0" # hrMemorySize.0 (Total RAM in KBytes, Gauge32)
OID_HR_STORAGE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4" # hrStorageFixedDisk OID

# OIDs for Interface Traffic
OID_IF_TABLE = "1.3.6.1.2.1.2.2.1"
OID_IF_DESCR = OID_IF_TABLE + ".2" # ifDescr
OID_IF_IN_OCTETS = OID_IF_TABLE + ".10" # ifInOctets
OID_IF_OUT_OCTETS = OID_IF_TABLE + ".16" # ifOutOctets


# Uyarı Eşikleri (Bunlar artık cihaz tabanlı olacak, ancak varsayılanlar burada kalabilir)
# CPU_ALERT_THRESHOLD = 80 # Yüzde (%)
# RAM_ALERT_THRESHOLD_PERCENT = 80 # Yüzde (%)
# DISK_ALERT_THRESHOLD_PERCENT = 90 # Yüzde (%)

# --- SNMP Yardımcı Fonksiyonları ---
def _get_snmp_value(ip, community, oid, type_prefix=None):
    """Tek bir SNMP OID'sinden değer çekmeye yardımcı fonksiyon."""
    try:
        # -On parametresi eklendi: Çıktıyı sayısal OID formatında zorlar
        cmd = ["snmpget", "-v2c", "-c", community, "-On", ip, oid]
        print(f"DEBUG: Running snmpget command: {' '.join(cmd)}") # DEBUG
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True)
        output = result.stdout.strip()
        print(f"DEBUG: snmpget stdout for {oid}: {output}") # DEBUG
        print(f"DEBUG: snmpget stderr for {oid}: {result.stderr.strip()}") # DEBUG

        if "No Such Instance" in output or "No Such Object" in output or "Timeout" in output:
            return None # OID bulunamadı veya zaman aşımı

        # type_prefix belirtilmişse, doğrudan o önekle ayrıştırmaya çalış
        if type_prefix:
            if type_prefix == "STRING":
                pattern = r"STRING:\s*\"?([^\"]+)\"?"
            elif type_prefix == "OID":
                pattern = r"OID:\s*(\S+)"
            elif type_prefix == "Timeticks":
                pattern = r"Timeticks: \((\d+)\)"
            elif type_prefix in ["Gauge32", "INTEGER", "Counter32", "Counter64"]:
                # Sayısal değerler ve opsiyonel birimler için daha esnek regex
                pattern = rf"{type_prefix}:\s*(\d+)(?:\s*\S*)?"
            elif type_prefix == "Float":
                pattern = r"Float:\s*([\d.]+)"
            elif type_prefix == "Hex-STRING":
                pattern = r"Hex-STRING:\s*(\S+)"
            elif type_prefix == "IpAddress":
                pattern = r"IpAddress:\s*(\S+)"
            else:
                pattern = rf"{type_prefix}:\s*(\S+)"

            match = re.search(pattern, output)
            if match:
                if type_prefix in ["STRING", "OID", "Hex-STRING", "IpAddress"]:
                    return match.group(1).strip()
                elif type_prefix == "Timeticks":
                    return int(match.group(1))
                elif type_prefix == "Float":
                    return float(match.group(1))
                else: # INTEGER, Gauge32, Counter32, Counter64
                    try:
                        return int(match.group(1))
                    except ValueError:
                        return None # Sayıya çevrilemezse None döndür
            else:
                return None # Belirtilen type_prefix ile eşleşme bulunamadı

        # Genel ayrıştırma (type_prefix belirtilmemişse veya eşleşmezse) - Fallback olarak kalabilir
        if "STRING:" in output:
            return output.split("STRING:")[-1].strip().strip('"')
        elif "INTEGER:" in output:
            match = re.search(r'INTEGER:\s*(\d+)(?:\s*\S*)?', output)
            if match:
                return int(match.group(1))
        elif "Gauge32:" in output:
            match = re.search(r'Gauge32:\s*(\d+)(?:\s*\S*)?', output)
            if match:
                return int(match.group(1))
        elif "Timeticks:" in output:
            match = re.search(r'Timeticks: \((\d+)\)', output)
            if match:
                return int(match.group(1))
        elif "OID:" in output:
            return output.split("OID:")[-1].strip()
        elif "Hex-STRING:" in output:
            return output.split("Hex-STRING:")[-1].strip().replace(" ", ":")
        elif "Counter32:" in output:
            match = re.search(r'Counter32:\s*(\d+)(?:\s*\S*)?', output)
            if match:
                return int(match.group(1))
        elif "Counter64:" in output:
            match = re.search(r'Counter64:\s*(\d+)(?:\s*\S*)?', output)
            if match:
                return int(match.group(1))
        elif "IpAddress:" in output:
            match = re.search(r'IpAddress:\s*(\S+)', output)
            if match:
                return match.group(1)
        elif "Float:" in output:
            match = re.search(r'Float:\s*([\d\.]+)', output)
            if match:
                return float(match.group(1))

        # Fallback: Herhangi bir sayısal değeri satırın sonından veya ortasından çekmeye çalış
        match_num = re.search(r'=\s*\S+:\s*(\d+)(?:\s*\S*)?', output)
        if match_num:
            return int(match_num.group(1))
        match_last_num = re.search(r'(\d+)$', output)
        if match_last_num:
            return int(match_last_num.group(1))

        return None
    except FileNotFoundError:
        print(f"DEBUG ERROR: snmpget command not found in PATH for OID {oid} from {ip}.")
        raise
    except subprocess.CalledProcessError as e:
        print(f"DEBUG: CalledProcessError for OID {oid} from {ip}: {e.stderr.strip()}")
        return None
    except subprocess.TimeoutExpired:
        print(f"DEBUG: TimeoutExpired for OID {oid} from {ip}")
        return None
    except Exception as e:
        print(f"DEBUG: General Exception in _get_snmp_value for OID {oid} from {ip}: {e}")
        return None

def _run_internet_speedtest():
    """Internet hız testini speedtest-cli ile çalıştırır ve sonuçları döndürür."""
    try:
        print("DEBUG (Flask): speedtest-cli komutu çalıştırılıyor...")
        process = subprocess.Popen(['speedtest', '--json'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=60)

        print(f"DEBUG (Flask): speedtest-cli stdout: {stdout.decode('utf-8')[:500]}...") # İlk 500 karakter
        print(f"DEBUG (Flask): speedtest-cli stderr: {stderr.decode('utf-8')}")
        print(f"DEBUG (Flask): speedtest-cli returncode: {process.returncode}")

        if process.returncode == 0:
            result = json.loads(stdout.decode('utf-8'))

            # Ham download/upload değerlerini loglayın
            raw_download_bps = result.get('download', 0)
            raw_upload_bps = result.get('upload', 0)
            print(f"DEBUG (Flask): Ham Download (bps): {raw_download_bps}")
            print(f"DEBUG (Flask): Ham Upload (bps): {raw_upload_bps}")

            download_mbps = round(raw_download_bps / 1_000_000, 2)
            upload_mbps = round(raw_upload_bps / 1_000_000, 2)
            ping_ms = round(result.get('ping', 0), 2)

            print(f"DEBUG (Flask): Hesaplanan Download (Mbps): {download_mbps}")
            print(f"DEBUG (Flask): Hesaplanan Upload (Mbps): {upload_mbps}")

            server_name = result.get('server', {}).get('name', 'Bilinmiyor')
            isp_name = result.get('client', {}).get('isp', 'Bilinmiyor') # 'isp' server altında değil, 'client' altında

            return {
                "success": True,
                "download": download_mbps,
                "upload": upload_mbps,
                "ping": ping_ms,
                "server_name": server_name,
                "isp": isp_name
            }
        else:
            print(f"ERROR (Flask): Speedtest çalıştırılırken hata: {stderr.decode('utf-8')}")
            return {"success": False, "error": stderr.decode('utf-8')}
    except FileNotFoundError:
        print("ERROR (Flask): 'speedtest' komutu bulunamadı. Lütfen 'speedtest-cli'nin yüklü olduğundan emin olun.")
        return {"success": False, "error": "'speedtest' komutu bulunamadı."}
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        print(f"ERROR (Flask): Speedtest zaman aşımına uğradı. Çıktı: {stdout.decode('utf-8')}, Hata: {stderr.decode('utf-8')}")
        return {"success": False, "error": "Speedtest zaman aşımına uğradı."}
    except json.JSONDecodeError as e:
        print(f"ERROR (Flask): Speedtest çıktısı JSON olarak ayrıştırılamadı: {e}. Çıktı: {stdout.decode('utf-8')}")
        return {"success": False, "error": f"Speedtest çıktısı ayrıştırma hatası: {e}"}
    except Exception as e:
        print(f"ERROR (Flask): Speedtest sırasında beklenmeyen hata: {e}")
        return {"success": False, "error": f"Beklenmeyen hata: {e}"}

# IP adresinden coğrafi konum bilgisi almak için yardımcı fonksiyon
def _get_geolocation(ip):
    """Bir IP adresinden coğrafi konum bilgisi çeker."""
    if ip in ["N/A", "timeout", ""] or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168."):
        return {"country": "Yerel/Özel Ağ", "city": "", "lat": None, "lon": None} # Özel veya yerel IP'ler için

    try:
        # ip-api.com ücretsiz servisini kullanıyoruz
        # Dikkat: Bu servisin rate limitleri (örn. dakikada 45 istek) olabilir.
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,isp")
        response.raise_for_status() # HTTP hataları için istisna fırlatır
        data = response.json()

        if data.get("status") == "success":
            return {
                "country": data.get("country", "Bilinmiyor"),
                "city": data.get("city", "Bilinmiyor"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp", "Bilinmiyor")
            }
        else:
            print(f"DEBUG: Geolocation API hatası for IP {ip}: {data.get('message', 'Bilinmeyen hata')}")
            return {"country": "Bilinmiyor", "city": "Bilinmiyor", "lat": None, "lon": None}
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Geolocation isteği başarısız oldu for IP {ip}: {e}")
        return {"country": "Bilinmiyor", "city": "Bilinmiyor", "lat": None, "lon": None}
    except json.JSONDecodeError:
        print(f"ERROR: Geolocation yanıtı JSON değil for IP {ip}")
        return {"country": "Bilinmiyor", "city": "Bilinmiyor", "lat": None, "lon": None}

def _snmpwalk_parse_table(ip, community, base_oid, column_oids, timeout=15):
    """
    snmpwalk çıktısını tablo formatında ayrıştırır.
    column_oids: {son_segment: anahtar_adı} şeklinde bir sözlük.
                 Örn: {'2': 'name', '4': 'path', '5': 'params'}
    """
    data_table = {}
    try:
        # -On parametresi eklendi: Çıktıyı sayısal OID formatında zorlar
        cmd = ["snmpwalk", "-v2c", "-c", community, "-On", ip, base_oid]
        print(f"DEBUG: Running snmpwalk command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
        lines = result.stdout.strip().splitlines()
        print(f"DEBUG: snmpwalk stdout for {base_oid}: {result.stdout.strip()[:500]}...")
        print(f"DEBUG: snmpwalk stderr for {base_oid}: {result.stderr.strip()}")

        for line in lines:
            try:
                parts = line.split(" = ")
                if len(parts) < 2: continue
                oid_full = parts[0].strip() # Örn: ".1.3.6.1.2.1.25.2.3.1.3.1"
                value_raw = parts[1].strip()

                # OID'nin son iki sayısal segmentini (sütun ve indeks) ayır
                # Örn: ".1.3.6.1.2.1.25.2.3.1.3.1" -> column_segment='3', idx='1'
                oid_segments = oid_full.split('.')
                if len(oid_segments) < 2: continue # En az bir sütun ve bir indeks olmalı

                idx = oid_segments[-1] # Son segment indeks
                column_segment = oid_segments[-2] # Sondan ikinci segment sütun

                if column_segment in column_oids:
                    key_name = column_oids[column_segment]
                    value = None

                    if "OID:" in value_raw:
                        oid_value = value_raw.split("OID:")[-1].strip()
                        # OID'den gelen değerler için daha spesifik dönüşümler
                        if "1.3.6.1.2.1.25.2.1.4" in oid_value: # hrStorageFixedDisk
                            value = 'Fixed Disk'
                        elif "1.3.6.1.2.1.25.2.1.2" in oid_value: # hrStorageRam
                            value = 'RAM'
                        elif "1.3.6.1.2.1.25.2.1.3" in oid_value: # hrStorageVirtualMemory
                            value = 'Virtual Memory'
                        elif "1.3.6.1.6.1.1" in oid_value: # ifTypeEthernetCsmacd (örnek OID, tam OID'yi kontrol edin)
                            value = 'ethernetCsmacd'
                        elif "1.3.6.1.6.1.24" in oid_value: # ifTypeSoftwareLoopback (örnek OID, tam OID'yi kontrol edin)
                            value = 'softwareLoopback'
                        else:
                            value = oid_value # Diğer OID'ler için ham değeri sakla
                    elif "INTEGER:" in value_raw:
                        match = re.search(r'INTEGER:\s*(\d+)(?:\s*\S*)?', value_raw)
                        if match:
                            value = int(match.group(1))
                    elif "Gauge32:" in value_raw:
                        match = re.search(r'Gauge32:\s*(\d+)(?:\s*\S*)?', value_raw)
                        if match:
                            value = int(match.group(1))
                    elif "STRING:" in value_raw:
                        value = value_raw.split("STRING:")[-1].strip().strip('"')
                    elif "Hex-STRING:" in value_raw:
                        value = value_raw.split("Hex-STRING:")[-1].strip().replace(" ", ":")
                    elif "Timeticks:" in value_raw:
                        match_ticks = re.search(r'Timeticks: \((\d+)\)', value_raw)
                        if match_ticks: value = int(match_ticks.group(1))
                    elif "Counter32:" in value_raw:
                        match_counter = re.search(r'Counter32:\s*(\d+)(?:\s*\S*)?', value_raw)
                        if match_counter: value = int(match.group(1))
                    elif "Counter64:" in value_raw:
                        match_counter64 = re.search(r'Counter64:\s*(\d+)(?:\s*\S*)?', value_raw)
                        if match_counter64: value = int(match.group(1))

                    if value is not None:
                        if idx not in data_table:
                            data_table[idx] = {}
                        data_table[idx][key_name] = value
            except Exception as e:
                print(f"DEBUG ERROR: Error parsing line in _snmpwalk_parse_table for OID {base_oid} from {ip}: {e}. Problematic line: {line}")
                continue
    except FileNotFoundError:
        print(f"DEBUG ERROR: snmpwalk command not found in PATH for OID {base_oid} from {ip}.")
        raise
    except subprocess.CalledProcessError as e:
        print(f"DEBUG ERROR: CalledProcessError in _snmpwalk_parse_table for OID {base_oid} from {ip}: {e.stderr.strip()}")
        raise
    except subprocess.TimeoutExpired:
        print(f"DEBUG ERROR: TimeoutExpired in _snmpwalk_parse_table for OID {base_oid} from {ip}.")
        raise
    except Exception as e:
        print(f"DEBUG ERROR: General Exception in _snmpwalk_parse_table for OID {base_oid} from {ip}: {e}")
        pass
    return data_table

# --- Arka Plan Görevi: SNMP Cihazlarını Sorgulama ve Uyarı Oluşturma ---
def poll_snmp_devices_job():
    print(f"[{datetime.now()}] SNMP cihazları taranıyor...")
    devices = db.get_all_devices()
    for device in devices:
        device_id = device['id']
        device_name = device['isim']
        ip = device['ip']
        community = device['community']
        
        # Cihazın kendi eşik değerlerini al, yoksa varsayılanları kullan
        cpu_threshold = device.get('cpu_threshold', 80.0)
        ram_threshold = device.get('ram_threshold', 80.0)
        disk_threshold = device.get('disk_threshold', 90.0)

        # CPU Kullanımı
        cpu_load_percent = -1

        cpu_load_1min = _get_snmp_value(ip, community, OID_CPU_LOAD_1MIN, type_prefix="Float")
        if cpu_load_1min is not None:
            cpu_load_percent = int(float(cpu_load_1min) * 10)
            message = f"CPU yük ortalaması (1dk): {cpu_load_1min}"
            
            hr_cpu_load = _get_snmp_value(ip, community, OID_CPU_LOAD, type_prefix="INTEGER")
            if hr_cpu_load is not None:
                cpu_load_percent = hr_cpu_load
                message = f"CPU kullanımı: {cpu_load_percent}% (hrDeviceProcessorLoad)"

            print(f"DEBUG: CPU for {device_name} ({ip}): {cpu_load_percent}%")

            if cpu_load_percent >= cpu_threshold: # Cihazın kendi eşiği kullanıldı
                db.add_alert(device_id, device_name, ip, "CPU", cpu_load_percent, cpu_threshold, message)
            else:
                db.check_and_resolve_alerts(device_id, "CPU", cpu_load_percent, cpu_threshold)
        else:
            message = "CPU verisi alınamadı."
            db.add_alert(device_id, device_name, ip, "CPU", -1, cpu_threshold, message) # Cihazın kendi eşiği kullanıldı


        # RAM Kullanımı
        ram_used_percent = -1
        total_ram_kbytes_from_oid = None # OID_MEMORY_SIZE'dan gelen toplam RAM (KB)
        ram_used_kbytes_calculated = None # hrStorageTable'dan hesaplanan kullanılan RAM (KB)

        try:
            total_ram_kbytes_from_oid = _get_snmp_value(ip, community, OID_MEMORY_SIZE, type_prefix="INTEGER")
            print(f"DEBUG: Toplam RAM (KB) (from OID_MEMORY_SIZE): {total_ram_kbytes_from_oid}")

            if total_ram_kbytes_from_oid is not None and total_ram_kbytes_from_oid > 0:
                hr_storage_column_oids = {
                    '2': 'type',
                    '3': 'descr',
                    '4': 'allocation_units',
                    '5': 'size',
                    '6': 'used'
                }
                storage_data = _snmpwalk_parse_table(ip, community, OID_HR_STORAGE_TABLE, hr_storage_column_oids)
                print(f"DEBUG: Storage Data for RAM calculation: {storage_data}")

                physical_memory_entry = None
                for idx, entry in storage_data.items():
                    if entry.get('type') == 'RAM' or entry.get('descr') == "Physical memory":
                        physical_memory_entry = entry
                        break
                
                if physical_memory_entry:
                    allocation_units = physical_memory_entry.get('allocation_units')
                    used_units = physical_memory_entry.get('used')
                    
                    if allocation_units is not None and used_units is not None:
                        # used_units * allocation_units = Bytes
                        # Bytes / 1024 = KBytes
                        ram_used_kbytes_calculated = (used_units * allocation_units) / 1024
                        print(f"DEBUG: Calculated Used RAM (KB): {ram_used_kbytes_calculated}")
                    else:
                        print("DEBUG: RAM allocation_units or used_units missing for physical memory entry.")

                if ram_used_kbytes_calculated is not None and total_ram_kbytes_from_oid > 0:
                    ram_used_percent = (ram_used_kbytes_calculated / total_ram_kbytes_from_oid) * 100
                    message = f"RAM kullanımı: {ram_used_percent:.2f}% (Toplam: {total_ram_kbytes_from_oid:.2f} KB, Kullanılan: {ram_used_kbytes_calculated:.2f} KB)"
                else:
                    message = "RAM kullanım detayı alınamadı (hrStorageTable üzerinden veya ayrıştırma hatası)."
            else:
                message = "Toplam RAM verisi alınamadı veya sıfır."

            print(f"DEBUG: RAM kullanım yüzdesi: {ram_used_percent}")
            sys.stdout.flush()
            # Alarmlar burada tetiklenir
            if ram_used_percent >= ram_threshold: # Cihazın kendi eşiği kullanıldı
                db.add_alert(device_id, device_name, ip, "RAM", ram_used_percent, ram_threshold, message)
            else:
                db.check_and_resolve_alerts(device_id, "RAM", ram_used_percent, ram_threshold) # Cihazın kendi eşiği kullanıldı

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            message = f"RAM sorgusu hatası: {e}"
            db.add_alert(device_id, device_name, ip, "RAM", -1, ram_threshold, message) # Cihazın kendi eşiği kullanıldı
            print(f"ERROR: RAM sorgusu hatası: {e}")
            sys.stdout.flush()
        except Exception as e:
            message = f"RAM verisi işlenirken hata: {e}"
            db.add_alert(device_id, device_name, ip, "RAM", -1, ram_threshold, message) # Cihazın kendi eşiği kullanıldı
            print(f"ERROR: RAM işleme hatası: {e}")
            sys.stdout.flush()


        # Disk Kullanımı (Örnek olarak '/' kök dizini)
        disk_usage_percent = -1
        disk_name = "/" # Şimdilik kök dizini izliyoruz
        
        # storage_data zaten RAM için çekildi, tekrar kullanabiliriz
        # Eğer RAM çekilirken hata olduysa, tekrar çekmek daha güvenli olabilir.
        # Ancak performans için mevcut veriyi kullanmaya devam edelim.
        # Eğer storage_data boşsa, disk verisi de alınamayacaktır.
        if 'storage_data' not in locals() or not storage_data:
             # Eğer RAM kısmı hata verdi ve storage_data oluşmadıysa, burada tekrar çekelim.
            hr_storage_column_oids = {
                '3': 'descr',
                '4': 'allocation_units',
                '5': 'size',
                '6': 'used',
                '2': 'type'
            }
            storage_data = _snmpwalk_parse_table(ip, community, OID_HR_STORAGE_TABLE, hr_storage_column_oids)
            print(f"DEBUG: Re-fetched Storage Data for Disk calculation: {storage_data}")


        disk_entry = None
        for idx, entry in storage_data.items():
            # Disk bölümlerini 'Fixed Disk' tipi ve '/' açıklaması ile bulmaya çalışıyoruz
            if entry.get('type') == 'Fixed Disk' and entry.get('descr') == disk_name:
                disk_entry = entry
                break

        if disk_entry:
            allocation_units = disk_entry.get('allocation_units')
            total_units = disk_entry.get('size')
            used_units = disk_entry.get('used')
            
            if allocation_units is not None and total_units is not None and used_units is not None and total_units > 0:
                total_disk_bytes = total_units * allocation_units
                used_disk_bytes = used_units * allocation_units
                
                total_disk_gb = total_disk_bytes / (1024**3)
                used_disk_gb = used_disk_bytes / (1024**3)

                disk_usage_percent = (used_disk_bytes / total_disk_bytes) * 100
                message = f"Disk ({disk_name}) kullanımı: {disk_usage_percent:.2f}% (Toplam: {total_disk_gb:.2f} GB, Kullanılan: {used_disk_gb:.2f} GB)"
            else:
                message = f"Disk ({disk_name}) detayları (boyut, kullanılan, birim) alınamadı veya eksik."
        else:
            message = f"Disk bölümü ({disk_name}) girişi bulunamadı (hrStorageTable üzerinden)."

        if disk_usage_percent >= disk_threshold: # Cihazın kendi eşiği kullanıldı
            db.add_alert(device_id, device_name, ip, "Disk", disk_usage_percent, disk_threshold, message)
        else:
            db.check_and_resolve_alerts(device_id, "Disk", disk_usage_percent, disk_threshold) # Cihazın kendi eşiği kullanıldı


        # Ağ Arayüzü Trafiği
        iface_table_column_oids = {
            '2': 'descr',
            '5': 'speed',
            '6': 'phys_address',
            '8': 'oper_status',
            '10': 'in_octets',
            '16': 'out_octets'
        }
        interface_data = _snmpwalk_parse_table(ip, community, OID_IF_TABLE, iface_table_column_oids)
        print(f"DEBUG: Parsed Interface Data for {ip}: {interface_data}")

        # Operasyonel durumları okunabilir stringlere çevir
        oper_status_map = {
            1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"
        }

        interfaces = [] # listeyi sıfırla
        for idx, i_item in interface_data.items():
            # Sadece açıklaması olan ve geçerli operasyonel duruma sahip arayüzleri al
            if i_item.get('descr') and i_item.get('oper_status') is not None:
                interfaces.append({
                    "index": idx, # JavaScript için indeks de eklendi
                    "descr": i_item.get('descr'),
                    "speed_mbps": round(i_item.get('speed', 0) / 1_000_000, 2) if i_item.get('speed') is not None else 'N/A',
                    "phys_address": i_item.get('phys_address'),
                    "oper_status": oper_status_map.get(i_item.get('oper_status'), 'Bilinmiyor'),
                    "in_octets": i_item.get('in_octets'),
                    "out_octets": i_item.get('out_octets')
                })
        if not interfaces:
            message = "Ağ Arayüz verisi alınamadı veya ayrıştırılamadı. Hedef cihazda Ağ Arayüz OID'si desteklenmiyor olabilir."
            db.add_alert(device_id, device_name, ip, "Network", -1, 0, message)
        
        print(f"DEBUG: Interfaces: {interfaces}")


# Uygulama başladığında ve kapanırken scheduler'ı yönet
scheduler.start()
# Uygulama kapanışında scheduler'ı düzgünce kapat
atexit.register(lambda: scheduler.shutdown())

# Rotaları kaydet (bu fonksiyon routes.py içinde tanımlanmalı)
routes.register_routes(app, _get_snmp_value, _snmpwalk_parse_table, _run_internet_speedtest) # Yardımcı fonksiyonları routes'a pass ediyoruz

# Scheduler'ı başlat
# Her 5 dakikada bir poll_snmp_devices_job fonksiyonunu çalıştır
scheduler.add_job(func=poll_snmp_devices_job, trigger="interval", minutes=5)

if __name__ == '__main__':
    # Bu blok sadece app.py doğrudan çalıştırıldığında tetiklenir (Gunicorn ile değil)
    app.run(debug=True, host='0.0.0.0')
